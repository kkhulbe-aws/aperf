#include "config.h"

#include <math.h>

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                     int group_fd, unsigned long flags) {
  int ret;
  ret = syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
  return ret;
}

void parse_arguments(int argc, char *argv[], struct arg_config *config) {
  config->period = DEFAULT_PERIOD;
  config->spe_period = (int)((double)GRV_FREQ / DEFAULT_SPE_FREQ);
  config->num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
  config->load_filter = DEFAULT_LOAD_FILTER;
  config->timeout = DEFAULT_TIMEOUT;
  config->throttle = 0; // no throttling by default
                        // currently unused, but if we notice
                        // CPU usage is higher than desired,
                        // we can add throttling

  static struct option long_options[] = {
      {"period", required_argument, 0, 'p'},
      {"spe_sample_frequency", required_argument, 0, 's'},
      {"timeout", required_argument, 0, 't'},
      {0, 0, 0, 0}};

  int option_index = 0;
  int c;

  while ((c = getopt_long(argc, argv, "p:s:t:", long_options,
                          &option_index)) != -1) {
    switch (c) {
    case 'p':
      config->period = atoi(optarg);
      break;
    case 's':
      config->spe_period = (int)((double)GRV_FREQ / atoi(optarg));
      break;
    case 't':
      config->timeout = atoi(optarg);
      break;
    case '?':
      printf(
          "Usage: ./<BINARY> --period X --spe_sample_frequency X --timeout X");
      break;
    default:
      printf("Invalid command provided.");
      printf(
          "Usage: ./<BINARY> --period X --spe_sample_frequency X --timeout X");
      cleanup_resources(config);
      exit(EXIT_FAILURE);
    }
  }
}

uint64_t get_cpu_part_num() {
  FILE *fp;
  char line[256];
  uint64_t part_num = 0;

  fp = fopen("/proc/cpuinfo", "r");
  if (fp == NULL) {
    perror("Error opening /proc/cpuinfo");
    return 0;
  }

  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "CPU part", 8) == 0) {
      sscanf(line, "CPU part\t: 0x%lx", &part_num);
      break;
    }
  }

  fclose(fp);
  return part_num;
}

void configure_cache_bins(struct arg_config *config) {

  switch (get_cpu_part_num()) {
  case GRV3:
    config->l1_bin = 5;  // 1.8 ns
    config->l2_bin = 16; // 5.7 ns
    config->l3_bin = 95; // 34 ns
    break;
  case GRV4:
    config->l1_bin = 4;  // 1.5 ns
    config->l2_bin = 14; // 5.0 ns
    config->l3_bin = 87; // 31 ns
    break;
  default:
    printf("Invalid CPU part number detected. \n");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }
}

// spe configurations were determined through several `strace` runs on `perf
// record`
void configure_ARM_SPE_cpu(int cpu, struct arm_spe_pmu *pmu,
                           struct arg_config *config) {
  long fd;
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
  attr.sample_period = config->spe_period;
  attr.sample_id_all = 1;
  attr.context_switch = 1;
  attr.aux_watermark = AUX_WATERMARK;
  attr.enable_on_exec = 1;
  attr.exclude_guest = 1;
  attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
  attr.config2 = config->load_filter;

  fd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
  if (fd == -1) {
    fprintf(stderr, "Error opening SPE perf event. Skipping Hotline. Are you "
                     "on Grv metal with kernel "
                     "drivers loaded?\n");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }
  pmu->fd = fd;
  pmu->cpu = cpu;
}

void mmap_ARM_SPE_cpu(struct arm_spe_pmu *pmu, struct arg_config *config) {
  uint64_t page_sz = getpagesize();
  uint64_t num_pages_required =
      4096; // independent of sampling period, and hard to predict due to
            // context switches, so we statically make it a large amount
  uint64_t mmap_data_size = num_pages_required * page_sz;
  uint64_t aux_size = GRV_FREQ * 1000 * config->period / config->spe_period *
                      16; // add overestimate of 16x to reduce probability of
                          // buffer overfill and data loss
  aux_size = (uint64_t)pow(2, ceil(log2((double)aux_size)));

  // add bounds so we don't have way too large (or small) buffers.
  if (aux_size < 15)
    aux_size = 1 << 15;
  else if (aux_size > 1 << 30)
    aux_size = 1 << 30;

  uint64_t aux_off = mmap_data_size + page_sz;
  struct perf_event_mmap_page *meta_page = NULL;
  if ((meta_page = (struct perf_event_mmap_page *)mmap(
           NULL, mmap_data_size + page_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
           pmu->fd, 0)) == MAP_FAILED) {
    fprintf(stderr, "mmap failed: %m\n");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }

  meta_page->aux_offset = aux_off;
  meta_page->aux_size = aux_size;

  void *aux_buffer = mmap(NULL, aux_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                          pmu->fd, aux_off);
  if (aux_buffer == MAP_FAILED) {
    fprintf(stderr, "mmap failed: %m\n");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }

  pmu->meta_page = meta_page;
  pmu->data_buffer = (char *)meta_page + PAGE_SIZE;
  pmu->aux_buffer = aux_buffer;
}

extern void configure_software_PMU(struct arm_spe_pmu *pmu,
                                   struct arg_config *config) {
  struct perf_event_attr attr;
  long fd;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_SW_DUMMY;
  attr.sample_period = config->spe_period;
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
  fd = perf_event_open(&attr, -1, pmu->cpu, -1, PERF_FLAG_FD_CLOEXEC);
  if (fd == -1) {
    fprintf(stderr, "Error opening SPE perf event. Skipping Hotline. Are you "
                     "on Grv metal with kernel "
                     "drivers loaded?\n");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }
  pmu->software_fd = fd;
}

// configure both hardware and software file descriptors for CPUs, mmap buffers
// for them, then configure them to be non-blocking
void configure_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config) {
  int ret;
  for (int i = 0; i < config->num_cpu; i++) {
    configure_ARM_SPE_cpu(i, &pmus[i], config);
    configure_software_PMU(&pmus[i], config);
    mmap_ARM_SPE_cpu(&pmus[i], config);
    ret = fcntl(pmus[i].fd, F_SETFL, O_RDONLY | O_NONBLOCK);
    if (ret == -1) {
      cleanup_resources(config);
      exit(EXIT_FAILURE);
    }
    ret = ioctl(pmus[i].software_fd, PERF_EVENT_IOC_SET_OUTPUT, pmus[i].fd);
    if (ret == -1) {
      cleanup_resources(config);
      exit(EXIT_FAILURE);
    }
    ret = fcntl(pmus[i].software_fd, F_SETFL, O_RDONLY | O_NONBLOCK);
    if (ret == -1) {
      cleanup_resources(config);
      exit(EXIT_FAILURE);
    }
  }
}

void toggle_pmu(struct arm_spe_pmu *pmu, uint64_t toggle,
                struct arg_config *config) {
  int ret;
  ret = ioctl(pmu->fd, PERF_EVENT_IOC_ENABLE, 0);
  if (ret == -1) {
    fprintf(stderr, "toggle failed on hardware PMU");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }
  ret = ioctl(pmu->software_fd, PERF_EVENT_IOC_ENABLE, 0);
  if (ret == -1) {
    fprintf(stderr, "toggle failed on software PMU");
    cleanup_resources(config);
    exit(EXIT_FAILURE);
  }
}

void enable_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config) {
  for (int i = 0; i < config->num_cpu; i++) {
    toggle_pmu(&pmus[i], PERF_EVENT_IOC_ENABLE, config);
  }
}

void disable_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config) {
  for (int i = 0; i < config->num_cpu; i++) {
    toggle_pmu(&pmus[i], PERF_EVENT_IOC_DISABLE, config);
  }
}

void reset_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config) {
  for (int i = 0; i < config->num_cpu; i++) {
    toggle_pmu(&pmus[i], PERF_EVENT_IOC_RESET, config);
  }
}

void configure_cpu_session(struct cpu_session *session,
                           struct arm_spe_pmu *pmu) {
  memset(session, 0,
         sizeof(struct cpu_session)); // zero everything out before populating
  session->conv.cap_user_time_short = 1;
  session->conv.cap_user_time_zero = 1;
  session->conv.time_cycles = pmu->meta_page->time_cycles;
  session->conv.time_mask = pmu->meta_page->time_mask;
  session->conv.time_mult = pmu->meta_page->time_mult;
  session->conv.time_shift = pmu->meta_page->time_shift;
  session->conv.time_zero = pmu->meta_page->time_zero;
  session->pid = 0;
  session->last_aux_ts = 0;
  session->last_aux_tail = 0;
  session->last_record_tail = 0;
  session->last_record_ts = 0;
}

void cleanup_resources(struct arg_config *config) {
  if (pmus) {
    for (int i = 0; i < config->num_cpu; i++) {
      struct arm_spe_pmu pmu = pmus[i];

      if (pmu.meta_page) {
        // get sizes directly from meta page
        uint64_t data_size =
            pmu.meta_page->data_offset + pmu.meta_page->data_size;
        uint64_t aux_size = pmu.meta_page->aux_size;

        // unmap aux buffer if it exists
        if (pmu.aux_buffer) {
          munmap(pmu.aux_buffer, aux_size);
          pmu.aux_buffer = NULL;
        }

        // unmap meta page and data buffer
        munmap(pmu.meta_page, data_size);
        pmu.meta_page = NULL;
        pmu.data_buffer = NULL;
      }

      // close the file descriptor if it's open
      if (pmu.fd >= 0) {
        close(pmu.fd);
        pmu.fd = -1;
      }
    }

    // free the PMU array itself
    free(pmus);
    pmus = NULL;
  }

  if (sessions) {
    free(sessions);
    sessions = NULL;
  }

  if (vm_spe_tr) {
    btree_free(vm_spe_tr);
    vm_spe_tr = NULL;
  }
  if (mapping_table) {
    free_pid_maps_table(mapping_table);
    mapping_table = NULL;
  }

  if (global_filenames) {
    free_global_filenames();
    global_filenames = NULL;
  }
}