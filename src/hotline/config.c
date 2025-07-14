#include "config.h"

/// @brief Exposed profile configuration after argument parsing
profile_config_t profile_configuration;

/// @brief Argument parsing logic for CLI input
void parse_arguments(int argc, char *argv[]) {
  static struct option long_options[] = {
      {"wakeup_period", required_argument, 0, 'p'},
      {"spe_sample_frequency", required_argument, 0, 's'},
      {"timeout", required_argument, 0, 't'},
      {"data_dir", required_argument, 0, 'd'},
      {"report_dir", required_argument, 0, 'r'},
      {"num_to_report", required_argument, 0, 'n'},
      {0, 0, 0, 0}};

  int option_index = 0;
  int c;

  // Set defaults
  profile_configuration.wakeup_period = PROFILE_DEFAULT_WAKEUP_PERIOD;
  profile_configuration.spe_sample_frequency = PROFILE_DEFAULT_SPE_SAMPLE_FREQ;
  profile_configuration.timeout = PROFILE_DEFAULT_TIMEOUT;
  // Assuming you've added these to your configuration struct
  profile_configuration.data_dir = strdup("./data");  // default data directory
  profile_configuration.report_dir =
      strdup("./report");  // default report directory

  profile_configuration.bmiss_map_filename = "hotline_bmiss_map.csv";
  profile_configuration.lat_map_filename = "hotline_lat_map.csv";
  profile_configuration.num_to_report = PROFILE_DEFAULT_NUM_REPORT;

  while ((c = getopt_long(argc, argv, "p:s:t:d:r:n:", long_options,
                          &option_index)) != -1) {
    switch (c) {
      case 'p':
        profile_configuration.wakeup_period = atoi(optarg);
        break;
      case 's':
        profile_configuration.spe_sample_frequency = atoi(optarg);
        break;
      case 't':
        profile_configuration.timeout = atoi(optarg);
        break;
      case 'd':
        free(profile_configuration.data_dir);  // Free default value
        profile_configuration.data_dir = strdup(optarg);
        break;
      case 'r':
        free(profile_configuration.report_dir);  // Free default value
        profile_configuration.report_dir = strdup(optarg);
        break;
      case 'n':
        profile_configuration.num_to_report = atoi(optarg);
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

  ASSERT(profile_configuration.wakeup_period > 0,
         "Wakeup period must be greater than 0");
  ASSERT(profile_configuration.spe_sample_frequency > 0 &&
             profile_configuration.spe_sample_frequency < MAX_SPE_SAMPLE_FREQ,
         "SPE sample frequency must be greater than 0");
  ASSERT(profile_configuration.timeout > 0, "Timeout must be greater than 0");
}

/// @brief computes the buffer sizes for the record and aux buffers
/// and returns it in a packaged struct.
/// @returns perf record buffer size, aux buffer size, and aux offset
void get_perf_buffer_sizes(perf_buffer_size_t *buffer_sizes) {
  uint64_t page_sz = cpu_system_config.page_size;
  uint64_t num_pages_required =
      4096 *
      profile_configuration
          .wakeup_period;  // independent of sampling period, and hard to
                           // predict due to context switches, so we statically
                           // make it a large amount profiling shows that this
                           // causes an increase in CPU util at the begining of
                           // the tool, during setup, but does not have much of
                           // an impact later onwards. We instead make it only
                           // proportional to the wakeup period

  uint64_t perf_record_buf_sz = num_pages_required * page_sz;
  uint64_t perf_aux_buf_sz = profile_configuration.spe_sample_frequency *
                             profile_configuration.wakeup_period *
                             sizeof(aux_record_raw_t) *
                             8;  // overestimate factor of 4x
  perf_aux_buf_sz = (uint64_t)pow(
      2,
      ceil(log2((double)perf_aux_buf_sz)));  // round it to a power of 2, as
                                             // required by perf_event_open docs

  uint64_t perf_aux_off = perf_record_buf_sz + page_sz;

  buffer_sizes->perf_record_buf_sz = perf_record_buf_sz;
  buffer_sizes->perf_aux_buf_sz = perf_aux_buf_sz;
  buffer_sizes->perf_aux_off = perf_aux_off;
}