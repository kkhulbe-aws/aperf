#ifndef CONFIG_H_
#define CONFIG_H_

#include "btree.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define GRV_FREQ 2800000000 // 2.8 GHz
#define GRV3 0xd40
#define GRV4 0xd4f

#define DEFAULT_PERIOD 1000   // in milliseconds
#define DEFAULT_SPE_FREQ 1000 // in Hz
#define DEFAULT_LOAD_FILTER 0
#define DEFAULT_TIMEOUT 60 // in seconds

// Referenced from ARM Neoverse V2 Core TRM, Section 22
// and ARM SPE Performance Analysis Methodology White Paper, Section 2
#define PERF_ARM_SPE_RAW_TYPE 0xc // ARM specific type
#define PERF_ARM_SPE_RAW_CONFIG                                                \
  0x10001 // enable load collection, branch collection
#define PERF_FORMAT_SPE 0x10

#define AUX_WATERMARK                                                          \
  64 // watermark notification for PERF_SAMPLE_AUX record generation
#define PAGE_SIZE 4096
#define NUM_PAGES 1024 // Increased from 128 to 1024
#define DATA_SIZE (NUM_PAGES * PAGE_SIZE)
#define AUX_SIZE (1024 * 1024 * 64) // 64 MB, increased from about 2 MB
#define AUX_OFFSET                                                             \
  (DATA_SIZE + PAGE_SIZE) // Ensure it's after data section and page-aligned

struct arg_config {
  uint32_t period;
  uint32_t spe_period;
  uint32_t num_cpu;
  uint32_t load_filter;
  uint32_t timeout;
  uint8_t throttle;
  uint64_t l1_bin;
  uint64_t l2_bin;
  uint64_t l3_bin;
};

struct arm_spe_pmu {
  uint64_t fd, software_fd, cpu;
  struct perf_event_mmap_page *meta_page;
  void *data_buffer;
  void *aux_buffer;
};

extern void parse_arguments(int argc, char *argv[], struct arg_config *config);

extern long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags);

struct perf_tsc_conversion {
  uint16_t time_shift;
  uint32_t time_mult;
  uint64_t time_zero;
  uint64_t time_cycles;
  uint64_t time_mask;

  int cap_user_time_zero;
  int cap_user_time_short;
};

struct cpu_session {
  pid_t pid; // most recent pid that we switched to
  struct perf_tsc_conversion conv;
  uint64_t last_aux_tail, last_record_tail;
  uint64_t last_aux_ts, last_record_ts;
};

/// @brief configures the hardware PMU event for SPE
/// @param cpu cpu number to open
/// @param pmu PMU metadata struct
/// @param config user supplied configuration
extern void configure_ARM_SPE_cpu(int cpu, struct arm_spe_pmu *pmu,
                                  struct arg_config *config);

/// @brief MMAPs data for the data and aux buffer for the provided PMU
/// @param pmu PMU metadata struct to mmap data for
/// @param config user supplied configuration
extern void mmap_ARM_SPE_cpu(struct arm_spe_pmu *pmu,
                             struct arg_config *config);

/// @brief configures the software PMU event for SPE, in order to get context
///        switch records
///        pipes the records into the hardware event for the cpu configured
///        by`configure_ARM_SPE_cpu`
/// @param pmu PMU metadata struct
/// @param config user supplied configuration
extern void configure_software_PMU(struct arm_spe_pmu *pmu,
                                   struct arg_config *config);

/// @brief Loops through all CPUs and sets them up
/// @param pmus PMU array
/// @param config user supplied configuration
extern void configure_all_pmus(struct arm_spe_pmu pmus[],
                               struct arg_config *config);

/// @brief functions to enable, disable, and reset all PMUs
/// @param pmus PMU array
/// @param config user supplied configuration
extern void enable_all_pmus(struct arm_spe_pmu pmus[],
                            struct arg_config *config);
extern void disable_all_pmus(struct arm_spe_pmu pmus[],
                             struct arg_config *config);
extern void reset_all_pmus(struct arm_spe_pmu pmus[],
                           struct arg_config *config);

/// @brief Default sets up a CPU session (active, potentially time-dependent,
///        CPU information)
/// @param session CPU session to configure
/// @param pmu PMU metadata struct
extern void configure_cpu_session(struct cpu_session *session,
                                  struct arm_spe_pmu *pmu);

extern void cleanup_resources(struct arg_config *config);

extern struct btree *vm_spe_tr;
extern char **global_filenames;
extern struct pid_maps_table *mapping_table;
extern struct arm_spe_pmu *pmus;
extern struct cpu_session *sessions;

#endif // CONFIG_H_