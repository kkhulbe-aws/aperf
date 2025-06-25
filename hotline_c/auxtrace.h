#ifndef AUXTRACE_H_
#define AUXTRACE_H_

#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "config.h"
#include "heap.h"
#include "btree.h"
#include <assert.h>
#include "mmap_table.h"

// Define the WITHIN macro
#define WITHIN(value, min, max) \
    ((value) >= (min) && (value) <= (max))

#define AUX_MAX_SIZE 4096

#define EINVALID_RECORD 1 << 0
#define ESATURATED_RECORD 1 << 1

#define AUX_SATURATED_WATERMARK 4095
#define AUX_RECORD_LOAD 0x49
#define AUX_RECORD_BRANCH 0x4a
#define AUX_RECORD_B_COND 0x01

#define EVENT_RETIRED 1 << 1
#define EVENT_BRANCH_NOT_TAKEN 1 << 6
#define EVENT_BRANCH_MISS 1 << 7

#define L1 0b0000
#define L2 0b1000
#define PEER_CORE 0b1001
#define LOCAL_CLUSTER 0b1010
#define SYSTEM_CACHE 0b1011
#define PEER_CLUSTER 0b1100
#define REMOTE 0b1101
#define DRAM 0b1110

#define L1_BOUND_BIN 5
#define L2_BOUND_BIN 15
#define L3_BOUND_BIN 50

#define THROTTLE_LIMIT 16000 // entries / second
                             // if set, we will only process 50k ordered entries. rest will be dropped
                             // given enough sampling time, the throttled method and unthrottled will converge
                             // this throttle allows THROTTLE_LIMIT record entries, and THROTTLE_LIMIT aux entries

struct spe_stats
{
    uint64_t aux_events, mmap2_events, itrace_events, switch_cpu_wide_events, exit_events, other;
    uint64_t malformed_entries;
    uint64_t saturated_entries;
};

struct sample_id
{
    uint32_t pid, tid;
    uint64_t time;
    uint32_t cpu, res;
    uint64_t id;
};

struct __attribute__((packed)) aux_record
{
    struct perf_event_header header;
    uint64_t aux_offset;
    uint64_t aux_size;
    uint64_t flags;
    struct sample_id sid;
};

struct __attribute__((packed)) spe_record
{
    uint8_t __reserved1;
    uint8_t pc[7];
    uint8_t __reserved2;
    uint8_t __reserved3[10];
    uint8_t type;
    uint8_t reg;
    uint8_t identifier;
    uint8_t events_packet[4];
    uint8_t __reserved4;
    uint8_t issue_lat[2];
    uint8_t __reserved5;
    uint8_t total_lat[2];
    uint64_t vaddr;
    uint8_t __reserved6;
    uint8_t __reserved7;
    uint8_t x_lat[2];
    uint8_t __reserved8[9];
    uint8_t __reserved9;
    uint8_t data_source;
    uint8_t __reserved10;
    uint8_t timestamp[8];
};

struct __attribute__((packed)) itrace_record
{
    struct perf_event_header header;
    uint32_t pid;
    uint32_t tid;
};

struct __attribute__((packed)) mmap2_record
{
    struct perf_event_header header;
    uint32_t pid;
    uint32_t tid;
    uint64_t addr;
    uint64_t len;
    uint64_t pgoff;
    union
    {
        struct
        {
            uint32_t maj;
            uint32_t min;
            uint64_t ino;
            uint64_t ino_generation;
        };

        struct
        {
            uint8_t bbuild_id_size;
            uint8_t __reserved_1;
            uint16_t __reserved_2;
            uint8_t build_id[20];
        };
    };

    uint32_t prot;
    uint32_t flags;
    char filename[];
};

struct __attribute__((packed)) switch_cpu_wide
{
    struct perf_event_header header;
    uint32_t next_prev_pid;
    uint32_t next_prev_tid;
    struct sample_id sid;
};

struct __attribute__((packed)) process_exit
{
    struct perf_event_header header;
    uint32_t pid, ppid;
    uint32_t tid, ptid;
    uint64_t time;
    struct sample_id sid;
};

struct aux_entry
{
    uint16_t type;
    uint64_t pc;
    uint16_t total_lat;
    uint16_t issue_lat;
    uint32_t saturated;
    uint32_t retired;
    union
    {
        struct
        {
            uint16_t x_lat;
            uint8_t data_source;
        } load;

        struct
        {
            uint16_t not_taken, mispredicted;
            uint8_t branch_type;
        } branch;
    };
};

struct ordered_sample
{
    uint16_t type;
    union
    {
        struct aux_entry aux_entry;
        // struct mmap2_record mmap2_entry;
        struct __attribute__((packed))
        {
            struct perf_event_header header;
            uint32_t pid;
            uint32_t tid;
            uint64_t addr;
            uint64_t len;
            uint64_t pgoff;
            union
            {
                struct
                {
                    uint32_t maj;
                    uint32_t min;
                    uint64_t ino;
                    uint64_t ino_generation;
                };

                struct
                {
                    uint8_t bbuild_id_size;
                    uint8_t __reserved_1;
                    uint16_t __reserved_2;
                    uint8_t build_id[20];
                };
            };

            uint32_t prot;
            uint32_t flags;
            uint64_t file_id;

        } mmap2_entry; // not just mmap2_record because we don't want to keep dragging around char[]
        struct switch_cpu_wide switch_entry;
        struct process_exit exit_entry;
    } sample;
};

extern long process_record_buffer(struct arm_spe_pmu *pmu, struct spe_stats *stats, struct cpu_session *session, uint32_t num_cpu, uint32_t spe_period, uint8_t should_throttle);
extern long drain_heap(struct cpu_session *session);

// returns nonzero code if record was invalid or unable to be processed
extern int process_record_aux(struct arm_spe_pmu *pmu, struct cpu_session *session, uint32_t num_cpu, uint32_t spe_period, uint8_t should_throttle);
extern int process_record_mmap2(struct mmap2_record *record);

// helpers
extern void parse_record(struct spe_record *record, struct aux_entry *entry);
extern uint64_t tsc_to_perf_time(uint64_t cyc, struct perf_tsc_conversion *tc);
extern int is_valid(enum perf_event_type type, void *record);
extern bool handle_aux_record(struct cpu_session *session, struct aux_entry *entry);

extern void traverse_buffers(struct arm_spe_pmu *pmu, struct cpu_session *session);
extern void upgrade_ts(struct arm_spe_pmu *pmu, struct cpu_session *session, uint64_t ts);

extern struct btree *vm_spe_tr;
extern struct pid_maps_table *mapping_table;

#endif // AUX_TRACE_H_;