#include "sys.h"

cpu_system_configuration_t CPU_SYSTEM_CONFIG;

FILE *open_cpu_info() {
  FILE *fp;
  fp = fopen("/proc/cpuinfo", "r");
  ASSERT(fp != NULL, "Error opening /proc/cpuinfo.");
  return fp;
}

uint64_t get_cpu_part() {
  FILE *fp = open_cpu_info();
  char line[256];
  uint64_t part;

  ASSERT(fp != NULL, "Unable to open CPU info.");

  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "CPU part", 8) == 0) {
      sscanf(line, "CPU part\t: 0x%lx", &part);
      break;
    }
  }

  fclose(fp);
  return part;
}

uint64_t get_page_size() { return getpagesize(); }

uint64_t get_frequency() {
  uint64_t part = get_cpu_part();

  switch (part) {
    case CPU_PART_ID_GRV3:
      return CPU_FREQ_GRV3;
    case CPU_PART_ID_GRV4:
      return CPU_FREQ_GRV4;
    default:
      ASSERT(0, "Unknown CPU part.");
      break;
  }
}

uint64_t get_num_cpus() { return sysconf(_SC_NPROCESSORS_ONLN); }

void get_latency_bins(completion_latency_limits_t *limits) {
  uint64_t part = get_cpu_part();

  switch (part) {
    case CPU_PART_ID_GRV3:
      limits->l1_max_cycles = 5;   // 1.8 ns
      limits->l2_max_cycles = 16;  // 5.7 ns
      limits->l3_max_cycles = 95;  // 34 ns
      break;
    case CPU_PART_ID_GRV4:
      limits->l1_max_cycles = 4;   // 1.5 ns
      limits->l2_max_cycles = 14;  // 5.0 ns
      limits->l3_max_cycles = 87;  // 31 ns
      break;
    default:
      ASSERT(0, "Unknown CPU part.");
      break;
  }
}

void init_sys_info() {
  CPU_SYSTEM_CONFIG.cpu_part = get_cpu_part();
  CPU_SYSTEM_CONFIG.frequency = get_frequency();
  CPU_SYSTEM_CONFIG.page_size = get_page_size();
  CPU_SYSTEM_CONFIG.num_cpus = get_num_cpus();

  get_latency_bins(&CPU_SYSTEM_CONFIG.latency_limits);
}