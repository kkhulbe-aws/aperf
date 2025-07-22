#pragma once

#include <stdint.h>

#include "finode_map.h"

#define CPU_FREQ_GRV2 2500000000  // 2.5 GHz
#define CPU_PART_ID_GRV2 0xd0c

#define CPU_FREQ_GRV3 2600000000  // 2.6 GHz
#define CPU_PART_ID_GRV3 0xd40

#define CPU_FREQ_GRV4 2800000000  // 2.8 GHz
#define CPU_PART_ID_GRV4 0xd4f

/// @brief Bins for grouping latencies by completion node
typedef struct completion_latency_limits {
  uint64_t l1_max_cycles;
  uint64_t l2_max_cycles;
  uint64_t l3_max_cycles;
} completion_latency_limits_t;

/// @brief Global struct to access system configuration
typedef struct cpu_system_configuration {
  uint64_t cpu_part;
  uint64_t page_size;
  uint64_t frequency;
  uint64_t num_cpus;
  completion_latency_limits_t latency_limits;
} cpu_system_configuration_t;

void init_sys_info();
void get_file_info(const char *filename, finode_t *finode);

/// @brief Exposed global system configuration for other modules to use
extern cpu_system_configuration_t cpu_system_config;