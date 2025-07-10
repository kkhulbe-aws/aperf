/**
 * @file config.h
 * @brief Argument passing and profiling configuration set up
 * @author Kaustubh Khulbe
 * @ingroup Graviton Software
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <getopt.h>
#include <stdint.h>

#include "hotline.h"
#include "log.h"
#include "sys.h"

#define PROFILE_DEFAULT_WAKEUP_PERIOD 1       // 1s
#define PROFILE_DEFAULT_SPE_SAMPLE_FREQ 1000  // 1kHz
#define PROFILE_DEFAULT_TIMEOUT 10            // 10s

typedef struct profile_config {
  uint32_t wakeup_period;
  uint32_t spe_sample_frequency;
  uint32_t timeout;
  char *data_dir;
  char *report_dir;
} profile_config_t;

typedef struct perf_buffer_size_t {
  uint64_t perf_record_buf_sz;
  uint64_t perf_aux_buf_sz;
  uint64_t perf_aux_off;
} perf_buffer_size_t;

void parse_arguments(int argc, char *argv[]);

void get_perf_buffer_sizes(perf_buffer_size_t *buffer_sizes);

extern profile_config_t PROFILE_CONFIGURATION;

#endif  // CONFIG_H_