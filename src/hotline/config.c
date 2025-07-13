#include "config.h"

/// @brief Exposed profile configuration after argument parsing
profile_config_t PROFILE_CONFIGURATION;

/// @brief Argument parsing logic for CLI input
void parse_arguments(int argc, char *argv[]) {
  static struct option long_options[] = {
      {"wakeup_period", required_argument, 0, 'p'},
      {"spe_sample_frequency", required_argument, 0, 's'},
      {"timeout", required_argument, 0, 't'},
      {"data_dir", required_argument, 0, 'd'},
      {"report_dir", required_argument, 0, 'r'},
      {0, 0, 0, 0}};

  int option_index = 0;
  int c;

  // Set defaults
  PROFILE_CONFIGURATION.wakeup_period = PROFILE_DEFAULT_WAKEUP_PERIOD;
  PROFILE_CONFIGURATION.spe_sample_frequency = PROFILE_DEFAULT_SPE_SAMPLE_FREQ;
  PROFILE_CONFIGURATION.timeout = PROFILE_DEFAULT_TIMEOUT;
  // Assuming you've added these to your configuration struct
  PROFILE_CONFIGURATION.data_dir = strdup("./data");  // default data directory
  PROFILE_CONFIGURATION.report_dir =
      strdup("./report");  // default report directory

  PROFILE_CONFIGURATION.bmiss_map_filename = "hotline_bmiss_map.csv";
  PROFILE_CONFIGURATION.lat_map_filename = "hotline_lat_map.csv";

  while ((c = getopt_long(argc, argv, "p:s:t:d:r:", long_options,
                          &option_index)) != -1) {
    switch (c) {
      case 'p':
        PROFILE_CONFIGURATION.wakeup_period = atoi(optarg);
        break;
      case 's':
        PROFILE_CONFIGURATION.spe_sample_frequency = atoi(optarg);
        break;
      case 't':
        PROFILE_CONFIGURATION.timeout = atoi(optarg);
        break;
      case 'd':
        free(PROFILE_CONFIGURATION.data_dir);  // Free default value
        PROFILE_CONFIGURATION.data_dir = strdup(optarg);
        break;
      case 'r':
        free(PROFILE_CONFIGURATION.report_dir);  // Free default value
        PROFILE_CONFIGURATION.report_dir = strdup(optarg);
        break;
      case '?':
        printf(
            "Usage: ./<BINARY> --wakeup_period X --spe_sample_frequency X "
            "--timeout X "
            "--data_dir path --report_dir path\n");
        exit(EXIT_FAILURE);
        break;
      default:
        printf("Invalid command provided.\n");
        printf(
            "Usage: ./<BINARY> --wakeup_period X --spe_sample_frequency X "
            "--timeout X "
            "--data_dir path --report_dir path\n");
        exit(EXIT_FAILURE);
    }
  }
}

/// @brief computes the buffer sizes for the record and aux buffers
/// and returns it in a packaged struct.
/// @returns perf record buffer size, aux buffer size, and aux offset
void get_perf_buffer_sizes(perf_buffer_size_t *buffer_sizes) {
  uint64_t page_sz = CPU_SYSTEM_CONFIG.page_size;
  uint64_t num_pages_required =
      8192;  // independent of sampling period, and hard to predict due to
             // context switches, so we statically make it a large amount

  uint64_t perf_record_buf_sz = num_pages_required * page_sz;
  uint64_t perf_aux_buf_sz = PROFILE_CONFIGURATION.spe_sample_frequency *
                             PROFILE_CONFIGURATION.wakeup_period *
                             sizeof(aux_record_raw_t) *
                             64;  // overestimate factor of 64x
  perf_aux_buf_sz = (uint64_t)pow(
      2,
      ceil(log2((double)perf_aux_buf_sz)));  // round it to a power of 2, as
                                             // required by perf_event_open docs
  if (perf_aux_buf_sz < 15)
    perf_aux_buf_sz = 1 << 15;
  else if (perf_aux_buf_sz > 1 << 30)
    perf_aux_buf_sz = 1 << 30;

  uint64_t perf_aux_off = perf_record_buf_sz + page_sz;

  buffer_sizes->perf_record_buf_sz = perf_record_buf_sz;
  buffer_sizes->perf_aux_buf_sz = perf_aux_buf_sz;
  buffer_sizes->perf_aux_off = perf_aux_off;
}