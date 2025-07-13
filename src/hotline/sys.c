#include "sys.h"

cpu_system_configuration_t cpu_system_config;

/// @brief Opens a file descriptor to cpuinfo
/// @return File Descriptor
FILE *open_cpu_info() {
  FILE *fp;
  fp = fopen("/proc/cpuinfo", "r");
  ASSERT(fp != NULL, "Error opening /proc/cpuinfo.");
  return fp;
}

/// @brief Uses the CPU file descriptor to read in the CPU part, so we can
/// assign latency bins
/// @return CPU part
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

/// @brief Wrapper for page size to standardize everything
uint64_t get_page_size() { return getpagesize(); }

/// @brief Gets the frequency of the machine in Hz using dmidecode
/// @return CPU Frequency in Hz
uint64_t get_frequency() {
  FILE *fp =
      popen("sudo dmidecode -t processor | grep 'Speed' | head -n1", "r");
  if (!fp) {
    ASSERT(0, "Failed to run dmidecode");
    return 0;
  }

  char line[256];
  uint64_t mhz = 0;

  if (fgets(line, sizeof(line), fp)) {
    // Line format: "Current Speed: 2400 MHz"
    char *speed_str = strstr(line, ":");
    if (speed_str) {
      mhz = strtoull(speed_str + 1, NULL, 10);  // +1 to skip the colon
    }
  }

  pclose(fp);

  ASSERT(mhz > 0, "Failed to get CPU frequency\n");

  return mhz * 1000000ULL;  // Convert MHz to Hz
}

/// @brief Wrapper to get num CPUs
uint64_t get_num_cpus() { return sysconf(_SC_NPROCESSORS_ONLN); }

/// @brief Read the part number to bin latencies, which are later used for
///        histogramming data.
/// @param limits Bin to populate
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

/// @brief Initializes global CPU_SYSTEM_CONFIG struct
void init_sys_info() {
  cpu_system_config.cpu_part = get_cpu_part();
  cpu_system_config.frequency = get_frequency();
  cpu_system_config.page_size = get_page_size();
  cpu_system_config.num_cpus = get_num_cpus();

  get_latency_bins(&cpu_system_config.latency_limits);
}

void get_file_info(const char *filename, finode_t *finode) {
  // Handle special cases
  if (strncmp(filename, "anon_inode:", 11) == 0 || filename[0] == '[') {
    finode->ino = 0;
    finode->maj = 0;
    finode->min = 0;
    finode->ino_generation = 0;
    return;
  }

  struct stat sb;
  if (lstat(filename, &sb) == -1) {
    finode->ino = 0;
    finode->maj = 0;
    finode->min = 0;
    finode->ino_generation = 0;
    return;
  }

  // General case
  finode->ino = sb.st_ino;
  dev_t dev = sb.st_dev;  // device containing the file
  finode->maj = major(dev);
  finode->min = minor(dev);
  finode->ino_generation = 0;
}
