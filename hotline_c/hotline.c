#include "hotline.h"

cpu_session_t *sessions = NULL;

/// @brief syscall wrapper for invoking the perf event open syscall
/// @param hw_event event attribute struct
/// @param pid pid to profile, -1 if pid independent
/// @param cpu cpu to profile, -1 if cpu independent
/// @param group_fd fd to forward data to
/// @param flags additional configuration flags
/// @return result of the syscall
uint64_t perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                         int group_fd, unsigned long flags) {
  int ret;
  ret = syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
  return ret;
}

/// @brief Initializes the hardware perf event for the PMU
/// @param session Active CPU session
void init_perf_hardware_event(cpu_session_t *session) {
  int fd;
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_ARM_SPE_RAW_TYPE;
  attr.config = PERF_ARM_SPE_RAW_CONFIG;
  attr.size = sizeof(attr);
  attr.disabled = 1;
  attr.inherit = 1;
  attr.read_format = PERF_FORMAT_ID | PERF_FORMAT_SPE;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
                     PERF_SAMPLE_CPU | PERF_SAMPLE_DATA_SRC |
                     PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_BRANCH_STACK;
  attr.sample_period =
      CPU_SYSTEM_CONFIG.frequency / PROFILE_CONFIGURATION.spe_sample_frequency;
  attr.sample_id_all = 1;
  attr.context_switch = 1;
  attr.aux_watermark = AUX_WATERMARK;
  attr.enable_on_exec = 1;
  attr.exclude_guest = 1;
  attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;

  // assign pid=-1 to profile for all processes, on this particular CPU
  fd = perf_event_open(&attr, -1, session->cpu, -1, PERF_FLAG_FD_CLOEXEC);
  ASSERT(fd != -1, "Failed to open perf hardware event.");

  session->hardware_fd = fd;
}

/// @brief Initializes the software perf event for the PMU, used for emitting
/// context switches/MMAP2/exits
/// @param session Active CPU session
void init_perf_software_event(cpu_session_t *session) {
  struct perf_event_attr attr;
  int fd;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_SW_DUMMY;
  attr.sample_period =
      CPU_SYSTEM_CONFIG.frequency / PROFILE_CONFIGURATION.spe_sample_frequency;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
                     PERF_SAMPLE_CPU | PERF_SAMPLE_IDENTIFIER;
  attr.read_format = PERF_FORMAT_ID | PERF_FORMAT_SPE;
  attr.disabled = 1;
  attr.inherit = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.mmap = 1;
  attr.comm = 1;
  attr.task = 1;
  attr.sample_id_all = 1;
  attr.exclude_guest = 1;
  attr.mmap2 = 1;
  attr.comm_exec = 1;
  attr.context_switch = 1;
  attr.ksymbol = 1;
  attr.bpf_event = 1;
  attr.watermark = 1;

  fd = perf_event_open(&attr, -1, session->cpu, -1, PERF_FLAG_FD_CLOEXEC);
  ASSERT(fd != -1, "Failed to open perf software event.");

  session->software_fd = fd;
}

/// @brief MMAPs record and aux buffers for the perf events
/// @param session Active CPU session
void mmap_perf_buffers(cpu_session_t *session) {
  perf_buffer_size_t buffer_sizes;
  get_perf_buffer_sizes(&buffer_sizes);

  struct perf_event_mmap_page *meta_page = (struct perf_event_mmap_page *)mmap(
      NULL, buffer_sizes.perf_record_buf_sz + CPU_SYSTEM_CONFIG.page_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, session->hardware_fd, 0);

  ASSERT(meta_page != MAP_FAILED, "Failed to mmap perf buffer.");

  meta_page->aux_offset = buffer_sizes.perf_aux_off;
  meta_page->aux_size = buffer_sizes.perf_aux_buf_sz;

  void *aux_buffer =
      mmap(NULL, buffer_sizes.perf_aux_buf_sz, PROT_READ | PROT_WRITE,
           MAP_SHARED, session->hardware_fd, buffer_sizes.perf_aux_off);

  ASSERT(aux_buffer != MAP_FAILED, "Failed to mmap aux buffer.");

  session->meta_page = meta_page;
  session->perf_record_buffer = (char *)meta_page + CPU_SYSTEM_CONFIG.page_size;
  session->perf_aux_buffer = aux_buffer;
}

/// @brief initializes the hardware and software perf events for a CPU session
void init_perf_events(cpu_session_t *session) {
  init_perf_hardware_event(session);
  init_perf_software_event(session);
  mmap_perf_buffers(session);

  int ret = fcntl(session->hardware_fd, F_SETFL, O_RDONLY | O_NONBLOCK);
  ASSERT(ret != -1, "Failed to set hardware event to non-blocking.");
  ret = ioctl(session->software_fd, PERF_EVENT_IOC_SET_OUTPUT,
              session->hardware_fd);
  ASSERT(ret != -1, "Failed to set software event output to hardware event.");
  ret = fcntl(session->software_fd, F_SETFL, O_RDONLY | O_NONBLOCK);
  ASSERT(ret != -1, "Failed to set software event to non-blocking.");
}

/// @brief Toggles the PMU to either enable, disable, or reset
/// @param session Active CPU session
/// @param toggle Flag to toggle to
void toggle_pmu(cpu_session_t *session, uint64_t toggle) {
  int ret;
  ret = ioctl(session->hardware_fd, toggle, 0);
  ASSERT(ret != -1, "Failed to toggle hardware PMU");
  ret = ioctl(session->software_fd, toggle, 0);
  ASSERT(ret != -1, "Failed to toggle software PMU");
}

/// @brief Configures the time conversions for the perf event so we can convert
/// from SPE to perf
/// @param session Active CPU session
void configure_session_conv(cpu_session_t *session) {
  session->conv.cap_user_time_short = 1;
  session->conv.cap_user_time_zero = 1;
  session->conv.time_cycles = session->meta_page->time_cycles;
  session->conv.time_mask = session->meta_page->time_mask;
  session->conv.time_mult = session->meta_page->time_mult;
  session->conv.time_shift = session->meta_page->time_shift;
  session->conv.time_zero = session->meta_page->time_zero;
}

/// @brief Initializes all the perf events for each CPU
void init_sessions() {
  sessions = malloc(sizeof(cpu_session_t) * CPU_SYSTEM_CONFIG.num_cpus);
  memset(sessions, 0, sizeof(cpu_session_t) * CPU_SYSTEM_CONFIG.num_cpus);
  ASSERT(sessions != NULL, "Failed to malloc sessions.");
  for (int i = 0; i < CPU_SYSTEM_CONFIG.num_cpus; i++) {
    sessions[i].cpu = i;
    init_perf_events(&sessions[i]);
    configure_session_conv(&sessions[i]);
  }
}

/// @brief Enables perf profiling across all CPUs
void enable_perf_profiling() {
  for (int i = 0; i < CPU_SYSTEM_CONFIG.num_cpus; i++) {
    toggle_pmu(&sessions[i], PERF_EVENT_IOC_ENABLE);
  }
}

/// @brief Conversion function from SPE time scale to Perf time scale, so we can
/// directly compare the two records.
/// referenced from linux perf: linux/tools/perf/util/tsc.c
/// @param cyc cycles in SPE time scale
/// @param tc conversion struct (populated during PMU setup)
/// @return perf time
uint64_t tsc_to_perf_time(uint64_t cyc, struct perf_tsc_conversion *tc) {
  uint64_t quot, rem;

  if (tc->cap_user_time_short)
    cyc = tc->time_cycles + ((cyc - tc->time_cycles) & tc->time_mask);

  quot = cyc >> tc->time_shift;
  rem = cyc & (((uint64_t)1 << tc->time_shift) - 1);
  return tc->time_zero + quot * tc->time_mult +
         ((rem * tc->time_mult) >> tc->time_shift);
}

/// @brief Given a perf record, gets the timestamp from it. Special care is
///       required for MMAP2 records. Returns `0` on no event found, and the
///       timestamp of the record.
uint64_t get_perf_event_timestamp(struct perf_event_header *header) {
  uint64_t timestamp = 0;
  switch (header->type) {
    case PERF_RECORD_AUX: {
      timestamp = ((aux_record_t *)header)->sid.time;
      break;
    }

    // We need to handle the PERF_RECORD_MMAP2 separately because of the `char
    // filename[];`. The sample sid struct is *after* the filename, so we use
    // full size of the record, offset it by the sample id, and extract the
    // timestamp.
    case PERF_RECORD_MMAP2: {
      mmap2_record_t *mmap2_rec = (mmap2_record_t *)header;
      size_t fixed_size = offsetof(mmap2_record_t, filename);
      size_t filename_len =
          header->size - fixed_size - sizeof(struct sample_id);
      sample_id_t *sid =
          (sample_id_t *)((char *)mmap2_rec + fixed_size + filename_len);
      timestamp = sid->time;
      break;
    }

    case PERF_RECORD_SWITCH_CPU_WIDE: {
      timestamp = ((switch_cpu_wide_record_t *)header)->sid.time;
      break;
    }

    case PERF_RECORD_EXIT: {
      timestamp = ((process_exit_record_t *)header)->sid.time;
      break;
    }

    default: {
      break;
    }
  }

  return timestamp;
}

/// @brief Processes a record for the perf record buffer
/// @param session Active CPU session
/// @param header Perf header for the record to process
void process_record_buffer_record(cpu_session_t *session,
                                  struct perf_event_header *header) {
  switch (header->type) {
    case PERF_RECORD_MMAP2: {
      struct mmap2_record *mmap2_rec = (struct mmap2_record *)header;
      size_t fixed_size = offsetof(struct mmap2_record, filename);
      size_t filename_len =
          header->size - fixed_size - sizeof(struct sample_id);

      char filename[filename_len + 1];
      memcpy(filename, ((char *)mmap2_rec) + fixed_size, filename_len);
      filename[filename_len] = '\0';

      // logic to update fname_map
      insert_fname_entry(mmap2_rec);
      break;
    }

    // if the switch is a SWITCH_OUT, the next_prev_pid is the process
    // that we are switching into.
    case PERF_RECORD_SWITCH_CPU_WIDE: {
      struct switch_cpu_wide_record *switch_rec =
          (struct switch_cpu_wide_record *)header;

      if ((switch_rec->header.misc & PERF_RECORD_MISC_SWITCH_OUT) != 0) {
        session->active_pid = switch_rec->next_prev_pid;
        // printf("SWITCHED TO PID: %u\n", session->active_pid);
      }

      break;
    }

    case PERF_RECORD_EXIT: {
      struct process_exit_record *exit = (struct process_exit_record *)header;

      // logic to remove pid from fname_map
      remove_fname_entry(exit->pid);
      break;
    }

    default: {
      break;
    }
  }
}

/// @brief Process a record for the AUX buffer
/// @param session Active CPU session
/// @param record Record to process
void process_aux_buffer_record(cpu_session_t *session,
                               aux_record_raw_t *record) {
  uint64_t pc;
  memcpy(&pc, &record->pc, 7);
  pc = pc & 0x00FFFFFFFFFFFFFF;  // zero out the top byte because
                                 // SPE PC is 7 bytes

  char *filename;
  uint64_t offset;
  // printf("HERE\n");
  int res = pc_to_file_offset(pc, session->active_pid, &filename, &offset);

  if (res != 0) {
    // printf("failed mapping\n");
    return;  // unable to map pc back to file/file offset
  }

  switch (record->type) {
    case AUX_PACKET_TYPE_LAT:
      lat_map_entry_t lat_entry;
      parse_lat_map_entry(record, &lat_entry, filename, offset);
      insert_lat_map_entry(&lat_entry);
      break;

    case AUX_PACKET_TYPE_BRANCH:
      bmiss_map_entry_t bmiss_entry;
      parse_bmiss_map_entry(record, &bmiss_entry, filename, offset);
      insert_bmiss_map(&bmiss_entry);
      break;
  }
}

/// @brief Process all the entries in the record buffer up to the `target_ts`
/// @param session Active CPU session
/// @param target_ts Timestamp to go up until
void process_record_buffer_up_to_ts(cpu_session_t *session,
                                    uint64_t target_ts) {
  char *data_page = session->perf_record_buffer;
  uint64_t data_head = session->meta_page->data_head;
  uint64_t data_tail =
      session->last_record_tail;  // use session's last position
  uint64_t data_size = session->meta_page->data_size;
  uint64_t last_ts =
      session
          ->last_record_ts;  // use the last recorded timestamp to continue from

  // "On SMP-capable platforms, after reading the data_head value, user space
  // should issue an rmb()."
  // https://man7.org/linux/man-pages/man2/perf_event_open.2.html
  asm volatile("dmb ishld" ::: "memory");  // memory barrier for reading

  while (data_tail < data_head) {
    if (data_tail + sizeof(struct perf_event_header) > data_head) {
      break;
    }

    struct perf_event_header *header =
        (struct perf_event_header *)(data_page + (data_tail % data_size));

    uint64_t record_ts = get_perf_event_timestamp(header);

    if (record_ts > target_ts) {
      break;  // don't process this record. Note, `record_ts = 0` records (i.e.
              // those that don't have a timestamp), are skippped.
    }

    if (record_ts > last_ts) {
      last_ts = record_ts;  // update the last processed timestamp
    }

    process_record_buffer_record(session, header);

    data_tail += header->size;
  }

  session->last_record_ts = last_ts;
  session->last_record_tail = data_tail;

  session->meta_page->data_tail = data_tail;
}

/// @brief Processes all the aux buffer entries for a CPU session
/// @param session Active CPU session
void process_aux_buffer(cpu_session_t *session) {
  void *aux = session->perf_aux_buffer;
  uint64_t aux_size = session->meta_page->aux_size;
  uint64_t aux_head = session->meta_page->aux_head;
  uint64_t aux_tail = session->last_aux_tail;

  // "On SMP-capable platforms, after reading the data_head value, user space
  // should issue an rmb()." The same must be done for the `aux_head`, according
  // to the docs. https://man7.org/linux/man-pages/man2/perf_event_open.2.html
  asm volatile("dmb ishld" ::: "memory");  // memory barrier for reading

  uint64_t last_processed_ts = 0;

  while (aux_tail + sizeof(aux_record_raw_t) <= aux_head) {
    aux_record_raw_t *record =
        (aux_record_raw_t *)(aux + (aux_tail % aux_size));

    uint64_t timestamp = record->timestamp;

    uint64_t perf_ts = tsc_to_perf_time(timestamp, &session->conv);

    if (perf_ts >= last_processed_ts) {
      process_record_buffer_up_to_ts(session, perf_ts);
      // at this point, we should have the current active PID, and all the
      // mappings should be updated

      process_aux_buffer_record(session, record);
      last_processed_ts = perf_ts;
    }

    aux_tail += sizeof(aux_record_raw_t);
    session->last_aux_tail = aux_tail;
    session->meta_page->aux_tail = aux_tail;
  }
}

/// @brief Serializes the LAT_MAP and BMISS_MAP into files
void serialize_maps() {
  char path[512];
  FILE *load_fp = NULL;
  FILE *branch_fp = NULL;
  struct btree_iter *iter = NULL;
  bool success = false;
  bool ok;

  // open load file
  int res = snprintf(path, sizeof(path), "%s/%s",
                     PROFILE_CONFIGURATION.data_dir, "hotline_lat_map.bin");
  ASSERT(res >= 0, "Failed to create load path.");
  load_fp = fopen(path, "w");

  // open branch file
  res = snprintf(path, sizeof(path), "%s/%s", PROFILE_CONFIGURATION.data_dir,
                 "hotline_bmiss_map.bin");
  ASSERT(res >= 0, "Failed to create branch path.");
  branch_fp = fopen(path, "w");

  ASSERT(load_fp != NULL && branch_fp != NULL, "Failed to open output files");

  // write headers
  res = fprintf(load_fp,
                "filename,offset,retired_insts,total_latency,issue_latency,"
                "translation_latency,"
                "l1_bin1,l1_bin2,l1_bin3,l1_bin4,"
                "l2_bin1,l2_bin2,l2_bin3,l2_bin4,"
                "l3_bin1,l3_bin2,l3_bin3,l3_bin4,"
                "dram_bin1,dram_bin2,dram_bin3,dram_bin4,saturated\n");
  ASSERT(res >= 0, "Failed to write load header.");

  res = fprintf(
      branch_fp,
      "filename,offset,retired_insts,not_taken_branches,"
      "mispredicted,total_latency,issue_latency,saturated,branch_type\n");
  ASSERT(res >= 0, "Failed to write branch header.");

  // write load entries
  iter = btree_iter_new(LAT_MAP);
  ok = btree_iter_seek(iter, &(lat_map_entry_t){});

  while (ok) {
    const lat_map_entry_t *entry = btree_iter_item(iter);

    int write_result = fprintf(
        load_fp,
        "%s,0x%lx,%lu,%lu,%lu,%lu,"
        "%lu,%lu,%lu,%lu,"        // l1 bins
        "%lu,%lu,%lu,%lu,"        // l2 bins
        "%lu,%lu,%lu,%lu,"        // l3 bins
        "%lu,%lu,%lu,%lu,%lu\n",  // dram bins
        entry->filename, entry->offset, entry->retired, entry->total_latency,
        entry->issue_latency, entry->translation_latency,
        entry->l1.l1_bound_bin, entry->l1.l2_bound_bin, entry->l1.l3_bound_bin,
        entry->l1.dram_bound_bin, entry->l2.l1_bound_bin,
        entry->l2.l2_bound_bin, entry->l2.l3_bound_bin,
        entry->l2.dram_bound_bin, entry->l3.l1_bound_bin,
        entry->l3.l2_bound_bin, entry->l3.l3_bound_bin,
        entry->l3.dram_bound_bin, entry->dram.l1_bound_bin,
        entry->dram.l2_bound_bin, entry->dram.l3_bound_bin,
        entry->dram.dram_bound_bin, entry->saturated);
    ok = btree_iter_next(iter);
    ASSERT(write_result >= 0, "Failed to write lat entry");
  }

  // write branch entries
  iter = btree_iter_new(BMISS_MAP);
  ok = btree_iter_seek(iter, &(bmiss_map_entry_t){});

  while (ok) {
    const bmiss_map_entry_t *entry = btree_iter_item(iter);

    int write_result =
        fprintf(branch_fp, "%s,0x%lx,%lu,%lu,%lu,%lu,%lu,%lu,%x\n",
                entry->filename, entry->offset, entry->retired,
                entry->not_taken, entry->mispredicted, entry->total_latency,
                entry->issue_latency, entry->saturated, entry->branch_type);
    ASSERT(write_result >= 0, "Failed to write branch entry");
    ok = btree_iter_next(iter);
  }
}

/// @brief Exposed wrapper function that APerf will call
/// @param argc Standard C like argc
/// @param argv Standard C like argv
void hotline(int argc, char *argv[]) {
  init_sys_info();
  parse_arguments(argc, argv);

  init_sessions();
  init_fname_map();
  init_lat_map();
  init_bmiss_map();

  int iters =
      PROFILE_CONFIGURATION.timeout / PROFILE_CONFIGURATION.wakeup_period;
  enable_perf_profiling();

  for (int i = 0; i < iters; i++) {
    sleep(PROFILE_CONFIGURATION.wakeup_period);
    for (int c = 0; c < CPU_SYSTEM_CONFIG.num_cpus; c++) {
      process_aux_buffer(&sessions[c]);
    }
  }

  serialize_maps();
}