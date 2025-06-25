#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/perf_event.h>
#include <errno.h>

#include "heap.h"

#define DEFAULT_PERIOD 1000         // in milliseconds
#define DEFAULT_SPE_PERIOD 2800000 // 1 kHz on Grv instances
#define DEFAULT_NUM_CPU 64         // cg7.metal instances
#define DEFAULT_LOAD_FILTER 0
#define DEFAULT_TIMEOUT 60         // in seconds

#define PERF_ARM_SPE_RAW_TYPE 0xc       // ARM specific type
#define PERF_ARM_SPE_RAW_CONFIG 0x10001 // enable load collection, branch collection, and load filtering
#define PERF_FORMAT_SPE 0x10

#define AUX_WATERMARK 64 // watermark notification for PERF_SAMPLE_AUX record generation
#define NUM_PAGES 64 * 2 // MUST be a power of two
#define PAGE_SIZE 4096
#define AUX_SIZE 131072 * 16
#define AUX_OFFSET 0x41000 * 16

struct arg_config
{
    uint32_t period;
    uint32_t spe_period;
    uint32_t num_cpu;
    uint32_t load_filter;
    uint32_t timeout;
    uint8_t throttle;
};

struct arm_spe_pmu
{
    uint64_t fd, software_fd, cpu;
    struct perf_event_mmap_page *meta_page;
    void *data_buffer;
    void *aux_buffer;
};

extern void parse_arguments(int argc, char *argv[], struct arg_config *config);

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    int ret;
    ret = syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
    return ret;
}

struct perf_tsc_conversion
{
    uint16_t time_shift;
    uint32_t time_mult;
    uint64_t time_zero;
    uint64_t time_cycles;
    uint64_t time_mask;

    int cap_user_time_zero;
    int cap_user_time_short;
};

struct cpu_session
{
    pid_t pid; // most recent pid that we switched to
    heap ordered_samples;
    struct perf_tsc_conversion conv;
    uint64_t last_aux_tail, last_record_tail;
    uint64_t last_aux_ts, last_record_ts;
};

extern long configure_ARM_SPE_cpu(int cpu, struct arm_spe_pmu *pmu, struct arg_config *config);
extern long mmap_ARM_SPE_cpu(struct arm_spe_pmu *pmu);
extern long configure_software_PMU(struct arm_spe_pmu *pmu, struct arg_config *config);
extern long configure_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config);
extern long enable_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config);
extern long disable_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config);
extern long reset_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config);
extern void configure_cpu_session(struct cpu_session *session, struct arm_spe_pmu *pmu);

#endif // CONFIG_H_