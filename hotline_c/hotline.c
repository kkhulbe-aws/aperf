#include "hotline.h"

/**
 * On every event loop:
 * 1. Loop through the AUX buffer, starting from where we left off on the
 * previous loop
 * 2. Upgrade the timestamp of the session by iterating through the record
 * buffer up to the timestamp right before the current AUX entry a. If it is
 * PERF_RECORD_SWITCH_CPU_WIDE: if it is a switch out, update the current
 * session pid b. If it is PERF_RECORD_MMAP2: update the mmap datastructures
 * with the new mappings c. If it is PERF_RECORD_EXIT: clean out the mmap
 * mappings for the corresponding pid
 *
 * The tool is implemented with this two pointer mechanism rather than a
 * min-heap because we observed the CPU utilization overhead of the minheap is
 * non-trivial, and can reach upwards of 9-11%, on worst-case workloads. This
 * mechanism has an observed worst-case of 2% and average of 1%, which motivates
 * enabling it by default on APerf.
 *
 * Architecture:
 *
 * +---------------+---------------+
 * |               |               |
 * | Record Buffer |  Aux Buffer  |
 * |               |               |
 * +---------------+---------------+
 *                 ^
 *                 |
 * +---------+    +-----------+    +-----------+
 * | Session |    |           |    | hotline   |
 * | current |----> Main loop <----+ B-Tree    |
 * |  PID    |    |           |    |           |
 * +---------+    +-----------+    +-----------+
 *                     ^                |
 *                     |                |
 *                     |                v
 *                +---------+           |
 *                |         |           |
 *                |MMAPings |<----------+
 *                |         |
 *                +---------+
 *
 * The B-Tree is what aggregates all the statistics for the user. In order to do
 * so, we need to know what the current pid is (hence the
 * PERF_RECORD_SWITCH_CPU_WIDE records), and a mapping structure for the virtual
 * address offsets. To ensure proper time ordering, everything is inserted into
 * the heap, pulled out, and processed in the corresponding data structures.
 *
 * The tool maintains a legacy implementation using the min-heap, and can be
 * swapped out for the two pointer method.
 */

// global variables
struct btree *vm_spe_tr = NULL; // main btree for all hotline entries
char **global_filenames = NULL; // global list of shared filenames
size_t global_filename_count = 0,
       global_filename_capacity = 0; // current amount of filenames used
struct pid_maps_table *mapping_table =
    NULL; // mapping table for the MMAP2 entries

// cpu, pmu, and configuration information
struct arm_spe_pmu *pmus;
struct cpu_session *sessions;
struct arg_config config;

// assigned via APerf as an environment variable when forking
const char *get_hotline_dir() {
  const char *env_dir = getenv("HOTLINE_DIR");
  return env_dir ? env_dir : "";
}

// assigned via APerf as an environment variable when building report
const char *get_hotline_report_dir() {
  const char *env_dir = getenv("HOTLINE_REPORT_DIR");
  return env_dir ? env_dir : "";
}

void signal_handler(int signum) {
  commit_to_file();
  exit(signum);
}

void commit_to_file(void) {
  char path[PATH_MAX];
  FILE *load_fp = NULL;
  FILE *branch_fp = NULL;
  struct btree_iter *iter = NULL;
  bool success = false;

  // open load file
  if (snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(),
               "spe_hotline_loads.bin") < 0) {
    rs_wrapper_error("Error creating load file path\n");
    return;
  }
  load_fp = fopen(path, "w");

  // open branch file
  if (snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(),
               "spe_hotline_branches.bin") < 0) {
    rs_wrapper_error("Error creating branch file path\n");
    goto cleanup;
  }
  branch_fp = fopen(path, "w");

  // verify file handles
  if (!load_fp || !branch_fp) {
    rs_wrapper_error("Error opening output files\n");
    goto cleanup;
  }

  // write headers
  if (fprintf(load_fp,
              "filename,offset,retired_insts,total_latency,issue_latency,"
              "translation_latency,"
              "l1_bin1,l1_bin2,l1_bin3,l1_bin4,"
              "l2_bin1,l2_bin2,l2_bin3,l2_bin4,"
              "l3_bin1,l3_bin2,l3_bin3,l3_bin4,"
              "dram_bin1,dram_bin2,dram_bin3,dram_bin4,saturated\n") < 0) {
    rs_wrapper_error("Error writing load header\n");
    goto cleanup;
  }

  if (fprintf(
          branch_fp,
          "filename,offset,retired_insts,not_taken_branches,"
          "mispredicted,total_latency,issue_latency,saturated,branch_type\n") <
      0) {
    rs_wrapper_error("Error writing branch header\n");
    goto cleanup;
  }

  // initialize btree iterator
  iter = btree_iter_new(vm_spe_tr);
  if (!iter) {
    rs_wrapper_error("Failed to create btree iterator\n");
    goto cleanup;
  }

  // process entries
  for (bool ok = btree_iter_first(iter); ok; ok = btree_iter_next(iter)) {
    struct vm_spe_btree_entry *entry =
        (struct vm_spe_btree_entry *)btree_iter_item(iter);

    if (!entry)
      continue;

    int write_result;
    if (entry->type == AUX_RECORD_LOAD) {
      write_result = fprintf(
          load_fp,
          "%s,0x%lx,%lu,%lu,%lu,%lu,"
          "%lu,%lu,%lu,%lu,"       // l1 bins
          "%lu,%lu,%lu,%lu,"       // l2 bins
          "%lu,%lu,%lu,%lu,"       // l3 bins
          "%lu,%lu,%lu,%lu,%lu\n", // dram bins
          global_filenames[entry->file_id], entry->offset, entry->retired_insts,
          entry->total_latency, entry->issue_latency,
          entry->load_entry.x_latency, entry->load_entry.l1.bin_1,
          entry->load_entry.l1.bin_2, entry->load_entry.l1.bin_3,
          entry->load_entry.l1.bin_4, entry->load_entry.l2.bin_1,
          entry->load_entry.l2.bin_2, entry->load_entry.l2.bin_3,
          entry->load_entry.l2.bin_4, entry->load_entry.l3.bin_1,
          entry->load_entry.l3.bin_2, entry->load_entry.l3.bin_3,
          entry->load_entry.l3.bin_4, entry->load_entry.dram.bin_1,
          entry->load_entry.dram.bin_2, entry->load_entry.dram.bin_3,
          entry->load_entry.dram.bin_4, entry->saturated_packets);
    } else if (entry->type == AUX_RECORD_BRANCH) {
      write_result =
          fprintf(branch_fp, "%s,0x%lx,%lu,%lu,%lu,%lu,%lu,%lu,%x\n",
                  global_filenames[entry->file_id], entry->offset,
                  entry->retired_insts, entry->branch_entry.not_taken_branches,
                  entry->branch_entry.mispredicted, entry->total_latency,
                  entry->issue_latency, entry->saturated_packets,
                  entry->branch_entry.branch_type);
    } else {
      continue;
    }

    if (write_result < 0) {
      rs_wrapper_error("Error writing entry to file\n");
      goto cleanup;
    }
  }

  success = true;

cleanup:
  if (load_fp)
    fclose(load_fp);
  if (branch_fp)
    fclose(branch_fp);
  if (iter)
    btree_iter_free(iter);

  cleanup_resources(&config);

  if (!success) {
    fprintf(stderr, "commit_to_file failed\n");
  }
}

/*
 * ----------------------------------------
 * functions to allow insertions and comparisons within the B-Tree to our custom
 * structs
 * ----------------------------------------
 */

/// @brief Compare function to make B-Tree operations possible
/// @param a first node to compare
/// @param b second node to compare
/// @param data auxiliary data (unused)
/// @return -1 if a < b, 1 if a > b, 0 if a == b
int vm_spe_btree_compare(const void *a, const void *b, void *data) {
  const struct vm_spe_btree_entry *a_entry =
      (const struct vm_spe_btree_entry *)a;
  const struct vm_spe_btree_entry *b_entry =
      (const struct vm_spe_btree_entry *)b;

  // bare minimum comparisons required to uniquely identify a VA to map SPE
  // records to
  if (a_entry->file_id < b_entry->file_id)
    return -1;
  else if (a_entry->file_id > b_entry->file_id)
    return 1;

  if (a_entry->offset < b_entry->offset)
    return -1;
  else if (a_entry->offset > b_entry->offset)
    return 1;

  if (a_entry->type < b_entry->type)
    return -1;
  else if (a_entry->type > b_entry->type)
    return 1;

  return 0;
}

/// @brief Iterator for the B-Tree. Used when committing to files. Always
/// returns true for
//         end-to-end iteration.
/// @param node (unused)
/// @param data (unused)
/// @return true
bool vm_spe_btree_iter(const void *node, const void *data) {
  struct vm_spe_btree_entry *entry = (struct vm_spe_btree_entry *)node;

  return true;
}

/*
 * ----------------------------------------
 * functions to allow managing files, create new MMAP mappings for pids, and
 * mapping addresses to file offsets using the mappings
 * ----------------------------------------
 */

/// @brief We maintain a global filestructure, since many processes can map to
/// the same file. This
///        function allows adding into it
/// @param filename filename to add into it
/// @return returns index at which file was added
size_t add_global_filename(const char *filename, struct arg_config *config) {
  // initialize if first use
  if (global_filenames == NULL) {
    global_filenames = malloc(INITIAL_SIZE * sizeof(char *));
    if (!global_filenames) {

      return (size_t)-1; // malloc failed
    }
    global_filename_capacity = INITIAL_SIZE;
  }

  // check if filename already exists
  for (size_t i = 0; i < global_filename_count; i++) {
    if (strcmp(global_filenames[i], filename) == 0) {
      return i;
    }
  }

  // grow array if needed
  if (global_filename_count >= global_filename_capacity) {
    size_t new_capacity = global_filename_capacity * 2;
    char **new_array = realloc(global_filenames, new_capacity * sizeof(char *));
    if (!new_array) {
      rs_wrapper_error("Failed re-allocation of global filenames. Exiting.\n");
      cleanup_resources(config);
      exit(EXIT_FAILURE);
    }
    global_filenames = new_array;
    global_filename_capacity = new_capacity;
  }

  // add new filename
  global_filenames[global_filename_count] = strdup(filename);
  if (!global_filenames[global_filename_count]) {
    rs_wrapper_error("Failed to update global filenames with file.\n");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }

  return global_filename_count++;
}

/// @brief Initializes data structures
/// @param config configuration struct to standardize cleanup
struct pid_maps_table *init_pid_maps(struct arg_config *config) {
  struct pid_maps_table *table = calloc(1, sizeof(struct pid_maps_table));
  if (!table) {
    rs_wrapper_error("Failed allocation of pid_maps_table. Exiting.\n");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }
  return table;
}

/// @brief accesses pid maps table
/// @param pid pid to get mappings for
/// @param config configuration struct to standardize cleanup
struct pid_maps *get_pid_maps(struct pid_maps_table *table, pid_t pid,
                              struct arg_config *config) {
  uint32_t hash = ((uint32_t)pid) % PID_MAP_HASH_SIZE;
  struct pid_maps *maps = table->buckets[hash];

  while (maps) {
    if (maps->pid == pid)
      return maps;
    maps = maps->next;
  }

  maps = calloc(1, sizeof(struct pid_maps));
  maps->pid = pid;
  maps->capacity = 16;
  maps->maps = malloc(maps->capacity * sizeof(struct map_entry));
  if (!maps->maps) {
    rs_wrapper_error("allocating maps for pid failed\n");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }
  maps->next = table->buckets[hash];
  table->buckets[hash] = maps;

  return maps;
}

/// @brief Logic to update the PID table given a new MMAP2 record
/// @param table Table to update
/// @param record MMAP2 record, read from the record buffer during
/// `process_aux_buffer`
/// @param config configuration struct to standardize cleanup
void process_mmap2_record(struct pid_maps_table *table,
                          const struct mmap2_mapping_entry *record,
                          struct arg_config *config) {
  struct pid_maps *maps = get_pid_maps(table, record->pid, config);

  if (maps->count >= maps->capacity) {
    maps->capacity *= 2;
    maps->maps = realloc(maps->maps, maps->capacity * sizeof(struct map_entry));

    if (!maps->maps) {
      rs_wrapper_error("reallocating maps failed\n");
      cleanup_resources(config);
      exit(EXIT_FAILURE);
    }
  }

  struct map_entry *entry = &maps->maps[maps->count];

  entry->start = record->addr;
  entry->end = record->addr + record->len;
  entry->pgoff = record->pgoff;
  entry->filename_index = record->file_id;

  maps->count++;
}

/// @brief Converts a given progarm counter to a filename and offset
/// @param maps PID datastructure associated with a PID
/// @param pc PC to translate
/// @param filename filename pointer to populate
/// @param file_offset file offset pointer to populate
/// @return 0 if no mapping found, 1 if successfully mapped
int pc_to_file_offset(struct pid_maps *maps, uint64_t pc, char **filename,
                      uint64_t *file_offset) {
  for (size_t i = 0; i < maps->count; i++) {
    if (pc >= maps->maps[i].start && pc < maps->maps[i].end) {
      *filename = global_filenames[maps->maps[i].filename_index];
      *file_offset = pc - maps->maps[i].start + maps->maps[i].pgoff;
      return 1;
    }
  }
  return 0;
}

/// @brief Frees, and accesses pid tables
void free_pid_maps_table(struct pid_maps_table *table) {
  for (int i = 0; i < PID_MAP_HASH_SIZE; i++) {
    struct pid_maps *maps = table->buckets[i];
    while (maps) {
      struct pid_maps *next = maps->next;
      free(maps->maps);
      free(maps);
      maps = next;
    }
  }
  free(table);
}

void free_global_filenames() {
  if (global_filenames) {
    for (size_t i = 0; i < global_filename_count; i++) {
      free(global_filenames[i]);
    }
    free(global_filenames);
    global_filenames = NULL;
    global_filename_count = 0;
    global_filename_capacity = 0;
  }
}

/// @brief Frees all the PID datastructures for a given PID
/// @param table table to clear up
/// @param pid PID to free
void free_pid_maps(struct pid_maps_table *table, pid_t pid) {
  if (!table)
    return;

  uint32_t hash = ((uint32_t)pid) % PID_MAP_HASH_SIZE;
  struct pid_maps *maps = table->buckets[hash];
  struct pid_maps *prev = NULL;

  while (maps) {
    if (maps->pid == pid) {
      // found the pid to remove
      if (prev) {
        // if not first in bucket, update previous node's next pointer
        prev->next = maps->next;
      } else {
        // if first in bucket, update bucket head
        table->buckets[hash] = maps->next;
      }

      // free the maps array and the pid_maps structure
      free(maps->maps);
      free(maps);
      return;
    }
    prev = maps;
    maps = maps->next;
  }
}

/// @brief We are not given MMAP2 records for already running processes. We
/// figure this out by
///        reading /proc/... to get all active processes and map them in.
/// @param table Table to map into
/// @param config configuration struct to standardize cleanup
void get_initial_mappings(struct pid_maps_table *table,
                          struct arg_config *config) {
  DIR *proc_dir;
  struct dirent *pid_entry;

  proc_dir = opendir("/proc");
  if (!proc_dir)
    return;

  while ((pid_entry = readdir(proc_dir))) {
    if (!isdigit(pid_entry->d_name[0]))
      continue;

    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%.230s/maps",
             pid_entry->d_name);

    FILE *maps = fopen(maps_path, "r");
    if (!maps)
      continue;

    pid_t pid = atoi(pid_entry->d_name);
    char line[1024];

    while (fgets(line, sizeof(line), maps)) {
      unsigned long start, end;
      unsigned long offset;
      char perms[5];
      char path[256] = "";

      sscanf(line, "%lx-%lx %4s %lx %*x:%*x %*u %255s", &start, &end, perms,
             &offset, path);

      if (path[0]) {
        struct mmap2_mapping_entry record = {
            .pid = pid, .addr = start, .len = end - start, .pgoff = offset};
        record.file_id = add_global_filename(path, config);

        process_mmap2_record(table, &record, config);
      }
    }

    fclose(maps);
  }

  closedir(proc_dir);
}

/*
 * ----------------------------------------
 * functions to handle parsing the two buffers (record and aux), and updating
 * respective data structures
 * ----------------------------------------
 */

/// @brief Takes a raw SPE packet entry and parses into a more manageable format
/// @param record raw data passed in
/// @param entry aux entry to populate
void parse_spe_record(struct raw_spe_record *record, struct aux_entry *entry) {
  // parsing logic to get what we want out of the record

  memset(entry, 0, sizeof(entry));

  uint64_t pc;
  memcpy(&pc, &record->pc, 7);
  pc = pc & 0x00FFFFFFFFFFFFFF; // zero out the top byte because
                                // SPE PC is 7 bytes

  entry->pc = pc;

  entry->type = record->type;

  entry->total_lat = record->total_lat;
  entry->issue_lat = record->issue_lat;

  // it is saturated if both issue_lat and total_lat = 4095
  if (entry->issue_lat == AUX_SATURATED_WATERMARK &&
      entry->total_lat == AUX_SATURATED_WATERMARK) {
    entry->saturated = 1;
  }

  uint32_t events_packet = record->events_packet;

  if (events_packet & EVENT_RETIRED)
    entry->retired = 1;

  // packet specific information for loads and branches
  if (record->type == AUX_RECORD_LOAD) {
    entry->load.data_source = record->data_source;
    entry->load.x_lat = record->x_lat;
  } else if (record->type == AUX_RECORD_BRANCH) {
    entry->branch.not_taken = (events_packet & EVENT_BRANCH_NOT_TAKEN) ? 1 : 0;
    entry->branch.mispredicted = (events_packet & EVENT_BRANCH_MISS) ? 1 : 0;

    entry->branch.branch_type = record->reg;
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

/// @brief Iterates through the record buffer, handling MMAP2, EXIT, and
/// SWITCH_CPU_WIDE records as they come
/// @param pmu PMU with the buffer pointers
/// @param session current CPU session
/// @param ts timestamp to upgrade to
void process_record_buffer(struct arm_spe_pmu *pmu, struct cpu_session *session,
                           uint64_t target_ts, struct arg_config *config) {
  char *data_page = ((char *)pmu->meta_page) + PAGE_SIZE;
  uint64_t data_head = pmu->meta_page->data_head;
  uint64_t data_tail = session->last_record_tail; // use session's last position
  uint64_t data_size = pmu->meta_page->data_size;
  uint64_t last_ts =
      session
          ->last_record_ts; // use the last recorded timestamp to continue from

  // ensure we don't read past the head
  // we process the records in two phases. We extract the timestamp,
  // and if it is before the `target_ts`, we handle the record.
  while (data_tail < data_head) {
    // check if we have enough space for at least a header
    if (data_tail + sizeof(struct perf_event_header) > data_head) {
      break;
    }

    struct perf_event_header *header =
        (struct perf_event_header *)(data_page + (data_tail % data_size));

    // validate header size
    if (header->size == 0 || data_tail + header->size > data_head) {
      break;
    }

    uint64_t current_ts = 0;

    // extract timestamp based on record type
    switch (header->type) {
    case PERF_RECORD_MMAP2: {
      struct mmap2_record *mmap2_rec = (struct mmap2_record *)header;
      size_t fixed_size = offsetof(struct mmap2_record, filename);
      size_t filename_len =
          header->size - fixed_size - sizeof(struct sample_id);
      struct sample_id *sid =
          (struct sample_id *)((char *)mmap2_rec + fixed_size + filename_len);
      current_ts = sid->time;
      break;
    }
    case PERF_RECORD_SWITCH_CPU_WIDE: {
      struct switch_cpu_wide_record *switch_rec =
          (struct switch_cpu_wide_record *)header;
      current_ts = switch_rec->sid.time;
      break;
    }
    case PERF_RECORD_EXIT: {
      struct process_exit_record *exit = (struct process_exit_record *)header;
      current_ts = exit->sid.time;
      break;
    }
    default:
      // skip unknown record types
      data_tail += header->size;
      continue;
    }

    // stop if we've reached a timestamp greater than our target
    if (current_ts > target_ts) {
      break;
    }

    // update last_ts if we have a valid timestamp
    if (current_ts > last_ts) {
      last_ts = current_ts;
    }

    // process the record based on its type
    switch (header->type) {
    case PERF_RECORD_MMAP2: {
      struct mmap2_record *mmap2_rec = (struct mmap2_record *)header;
      size_t fixed_size = offsetof(struct mmap2_record, filename);
      size_t filename_len =
          header->size - fixed_size - sizeof(struct sample_id);

      struct unified_buffer_entry os;

      memcpy(&(os.sample.mmap2_entry), mmap2_rec, fixed_size);

      if (filename_len > 0) {
        char filename[filename_len + 1];
        memcpy(filename, ((char *)mmap2_rec) + fixed_size, filename_len);
        filename[filename_len] = '\0'; // ensure null termination
        os.sample.mmap2_entry.file_id = add_global_filename(filename, config);
      }

      os.type = PERF_RECORD_MMAP2;
      process_mmap2_record(mapping_table,
                           (struct mmap2_mapping_entry *)&os.sample.mmap2_entry,
                           config);
      break;
    }

    case PERF_RECORD_SWITCH_CPU_WIDE: {
      struct switch_cpu_wide_record *switch_rec =
          (struct switch_cpu_wide_record *)header;
      if (switch_rec->header.misc & PERF_RECORD_MISC_SWITCH_OUT) {
        if (switch_rec->next_prev_pid >= 0 &&
            switch_rec->next_prev_pid < ((2 << 21) - 1)) {
          session->pid = switch_rec->next_prev_pid;
        }
      }
      break;
    }

    case PERF_RECORD_EXIT: {
      struct process_exit_record *exit = (struct process_exit_record *)header;
      free_pid_maps(mapping_table, exit->pid);
      break;
    }
    }

  next_record:
    data_tail += header->size;
    asm volatile("dmb ishld" ::: "memory"); // memory barrier for reading
  }

  // update session state
  session->last_record_ts = last_ts;
  session->last_record_tail = data_tail;
  pmu->meta_page->data_tail = data_tail;
}

/// @brief The bulk of the CPU time goes into this. Loops through the aux buffer
/// from the last read
///        tail to the current head. Every aux entry it will upgrade the
///        timestamp, i.e. process the
//         record buffer up to the last entry before this time stamp.
/// @param pmu PMU with the buffer pointers
/// @param config CPU configurations, used for cache binning
/// @param session current CPU session
void process_aux_buffer(struct arm_spe_pmu *pmu, struct cpu_session *session,
                        struct arg_config *config) {
  void *aux = pmu->aux_buffer;
  uint64_t aux_size = pmu->meta_page->aux_size;
  uint64_t aux_head = pmu->meta_page->aux_head;
  uint64_t aux_tail = session->last_aux_tail;

  uint64_t last_processed_ts = 0;

  // ensure we don't read past the head
  while (aux_tail + sizeof(struct raw_spe_record) <= aux_head) {
    struct raw_spe_record *record =
        (struct raw_spe_record *)(aux + (aux_tail % aux_size));

    uint64_t timestamp = record->timestamp;

    uint64_t perf_ts = tsc_to_perf_time(timestamp, &session->conv);

    // only process if this timestamp is greater than our last processed
    // timestamp. Edge case guard for buffer wrap arounds.
    if (perf_ts >= last_processed_ts) {
      struct aux_entry entry;
      parse_spe_record(record, &entry);

      // process all records up to this timestamp
      process_record_buffer(pmu, session, perf_ts, config);

      // process the aux record itself
      process_aux_record(session, &entry, config);

      last_processed_ts = perf_ts;
    }

    aux_tail += sizeof(struct raw_spe_record);
    session->last_aux_tail = aux_tail;
    pmu->meta_page->aux_tail = aux_tail;
    asm volatile("dmb ishld" ::: "memory"); // read memory fence
  }
}

/// @brief Utility function to update the B-Tree based on the aux entry
/// provided. Updates the
///        branch or load entries for a given PC based on the aux_entry flags.
/// @param session current CPU session
/// @param entry aux entry to update with
/// @param config CPU configurations, used for cache binning
/// @return true if the record was successfully put into the B-Tree, false
/// otherwise
int process_aux_record(struct cpu_session *session, struct aux_entry *entry,
                       struct arg_config *config) {
  pid_t pid = session->pid;
  struct pid_maps *maps = get_pid_maps(mapping_table, pid, config);
  char *filename;
  uint64_t file_off;

  if (pc_to_file_offset(maps, entry->pc, &filename, &file_off)) {
    // this branch is when we successfully map a pc
    // based on if it is a branch or load packet we handle it differently
    // 1. convert to a PC
    // 2. if successful, request the entry from the btree
    // 3. modify that entry (or create a new one if it doesn't exist) based on
    // load or branch
    // 4. insert into btree

    uint64_t file_id = add_global_filename(filename, config);
    struct vm_spe_btree_entry key = {
        .file_id = file_id, .offset = file_off, .type = entry->type};

    const struct vm_spe_btree_entry *btree_entry = btree_get(vm_spe_tr, &key);
    struct completion_hist l1, l2, l3, dram;

    struct vm_spe_btree_entry new_entry;
    memset(&new_entry, 0, sizeof(struct vm_spe_btree_entry));

    new_entry.type = entry->type;
    new_entry.file_id = file_id;
    new_entry.offset = file_off;

    // if saturated, copy over the current btree entry (we're not updating
    // statistics if saturated) if the entry exists and increment saturated
    // by 1.
    if (entry->saturated == 1) {
      if (btree_entry)
        memcpy(&new_entry, &btree_entry, sizeof(struct vm_spe_btree_entry));
      new_entry.saturated_packets =
          btree_entry ? btree_entry->saturated_packets + 1 : 1;
      btree_set(vm_spe_tr, &new_entry);
      return false;
    }

    // these are entries common to both AUX_RECORD_LOAD and AUX_RECORD_BRANCH
    new_entry.retired_insts = btree_entry ? btree_entry->retired_insts + 1 : 1;
    new_entry.total_latency =
        btree_entry ? btree_entry->total_latency + entry->total_lat
                    : entry->total_lat;
    new_entry.issue_latency =
        btree_entry ? btree_entry->issue_latency + entry->issue_lat
                    : entry->issue_lat;

    new_entry.saturated_packets =
        btree_entry ? btree_entry->saturated_packets : 0;

    if (entry->type == AUX_RECORD_LOAD) {
      struct completion_hist l1, l2, l3, dram;

      if (btree_entry == NULL) {
        memset(&l1, 0, sizeof(struct completion_hist));
        memset(&l2, 0, sizeof(struct completion_hist));
        memset(&l3, 0, sizeof(struct completion_hist));
        memset(&dram, 0, sizeof(struct completion_hist));
      } else {
        l1 = btree_entry->load_entry.l1;
        l2 = btree_entry->load_entry.l2;
        l3 = btree_entry->load_entry.l3;
        dram = btree_entry->load_entry.dram;
      }

      // this logic first determines which bin to increment based on the data
      // source then based on the latency increments within the sub-bin for that
      struct completion_hist *bin = NULL;
      uint16_t execution_latency =
          entry->total_lat - entry->issue_lat - entry->load.x_lat;

      switch (entry->load.data_source) {
      case (L1):
        bin = &l1;
        break;
      case (L2):
        bin = &l2;
        break;
      // assign LOCAL_CLUSTER, PEER_CLUSTER, and SYSTEM_CACHE to L3
      case (LOCAL_CLUSTER):
      case (PEER_CLUSTER):
      case (SYSTEM_CACHE):
        bin = &l3;
        break;
      // assign REMOTE and DRAM to DRAM
      case (REMOTE):
      case (DRAM):
        bin = &dram;
        break;
      }

      if (execution_latency < config->l1_bin)
        bin->bin_1++;
      else if (execution_latency < config->l2_bin)
        bin->bin_2++;
      else if (execution_latency < config->l3_bin)
        bin->bin_3++;
      else
        bin->bin_4++;

      new_entry.load_entry.x_latency =
          btree_entry ? btree_entry->load_entry.x_latency + entry->load.x_lat
                      : entry->load.x_lat;
      new_entry.load_entry.l1 = l1;
      new_entry.load_entry.l2 = l2;
      new_entry.load_entry.l3 = l3;
      new_entry.load_entry.dram = dram;
      btree_set(vm_spe_tr, &new_entry);
      return true;
    } else if (entry->type == AUX_RECORD_BRANCH) {
      new_entry.branch_entry.not_taken_branches =
          btree_entry ? btree_entry->branch_entry.not_taken_branches +
                            entry->branch.not_taken
                      : entry->branch.not_taken;
      new_entry.branch_entry.mispredicted =
          btree_entry ? btree_entry->branch_entry.mispredicted +
                            entry->branch.mispredicted
                      : entry->branch.mispredicted;
      new_entry.branch_entry.branch_type = entry->branch.branch_type;
      btree_set(vm_spe_tr, &new_entry);
      return true;
    }
    return false;
  }
  return false;
}

// main function that is exposed to the user (APerf)
int hotline_main(int argc, char *argv[]) {
  memset(&config, 0, sizeof(struct arg_config));
  struct arm_spe_pmu *pmus = NULL;
  struct cpu_session *sessions = NULL;

  // parse arguments
  parse_arguments(argc, argv, &config);
  configure_cache_bins(&config);

  // allocate PMU and session arrays
  pmus = calloc(config.num_cpu, sizeof(struct arm_spe_pmu));
  if (!pmus) {
    rs_wrapper_error("Failed to allocate PMU array");
    return EXIT_FAILURE;
  }

  sessions = calloc(config.num_cpu, sizeof(struct cpu_session));
  if (!sessions) {
    rs_wrapper_error("Failed to allocate session array");
    cleanup_resources(&config);
    return EXIT_FAILURE;
  }

  // configure signal handling
  struct sigaction sa = {.sa_handler = signal_handler, .sa_flags = 0};
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGTERM, &sa, NULL) == -1) {
    rs_wrapper_error("Cannot handle SIGTERM");
    cleanup_resources(&config);
    return EXIT_FAILURE;
  }

  // initialize and configure PMUs
  configure_all_pmus(pmus, &config);
  reset_all_pmus(pmus, &config);

  // configure CPU sessions
  for (int i = 0; i < config.num_cpu; i++) {
    configure_cpu_session(&sessions[i], &pmus[i]);
  }

  // initialize btree
  vm_spe_tr = btree_new(sizeof(struct vm_spe_btree_entry), 0,
                        vm_spe_btree_compare, NULL);
  btree_clear(vm_spe_tr);

  // initialize mapping table and read /proc/map to get all currently running
  // processes this is needed as currently running processes do not generate
  // MMAP2 records
  mapping_table = init_pid_maps(&config);
  get_initial_mappings(mapping_table, &config);

  enable_all_pmus(pmus, &config);

  // main event loop
  uint64_t iters = config.timeout / ((double)config.period / 1000);
  for (int itr = 0; itr < iters; itr++) {
    sleep(config.period);

    for (int i = 0; i < config.num_cpu; i++) {
      process_aux_buffer(&pmus[i], &sessions[i], &config);
    }
  }

  // cleanup and exit
  disable_all_pmus(pmus, &config);
  commit_to_file();
  cleanup_resources(&config);
  return EXIT_SUCCESS;
}