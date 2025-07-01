#ifndef AUXTRACE_H_
#define AUXTRACE_H_

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btree.h"
#include "config.h"
#include "mmap_table.h"

// Define the WITHIN macro
#define WITHIN(value, min, max) ((value) >= (min) && (value) <= (max))

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

#define THROTTLE_LIMIT                                                         \
  64000 // entries / second
        // if set, we will only process 50k ordered entries. rest will be
        // dropped given enough sampling time, the throttled method and
        // unthrottled will converge this throttle allows THROTTLE_LIMIT record
        // entries, and THROTTLE_LIMIT aux entries
#define AUX_THROTTLE_LIMIT 24000 // entries / second

#define GRV3 0xd40
#define GRV4 0xd4f

/// @brief overall statistics counters, for debugging the tool
struct spe_stats {
  uint64_t aux_events, mmap2_events, itrace_events, switch_cpu_wide_events,
      exit_events, other;
  uint64_t malformed_entries;
  uint64_t saturated_entries;
};

/// @brief sample_id struct spec from
/// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
struct sample_id {
  uint32_t pid, tid;
  uint64_t time;
  uint32_t cpu, res;
  uint64_t id;
};

/// @brief aux record spec from
/// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
struct __attribute__((packed)) aux_record {
  struct perf_event_header header;
  uint64_t aux_offset;
  uint64_t aux_size;
  uint64_t flags;
  struct sample_id sid;
};

/// @brief spe_record spec from observing perf reports and ARM docs
struct __attribute__((packed)) spe_record {
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

/// @brief itrace_record spec from
/// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
struct __attribute__((packed)) itrace_record {
  struct perf_event_header header;
  uint32_t pid;
  uint32_t tid;
};

/// @brief mmap2 record spec from
/// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
struct __attribute__((packed)) mmap2_record {
  struct perf_event_header header;
  uint32_t pid;
  uint32_t tid;
  uint64_t addr;
  uint64_t len;
  uint64_t pgoff;
  union {
    struct {
      uint32_t maj;
      uint32_t min;
      uint64_t ino;
      uint64_t ino_generation;
    };

    struct {
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

/// @brief switch_cpu_wide spec from
/// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
struct __attribute__((packed)) switch_cpu_wide {
  struct perf_event_header header;
  uint32_t next_prev_pid;
  uint32_t next_prev_tid;
  struct sample_id sid;
};

/// @brief process_exit spec from
/// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
struct __attribute__((packed)) process_exit {
  struct perf_event_header header;
  uint32_t pid, ppid;
  uint32_t tid, ptid;
  uint64_t time;
  struct sample_id sid;
};

struct aux_entry {
  uint16_t type;
  uint64_t pc;
  uint16_t total_lat;
  uint16_t issue_lat;
  uint8_t saturated;
  uint32_t retired;
  union {
    struct {
      uint16_t x_lat;
      uint8_t data_source;
    } load;

    struct {
      uint16_t not_taken, mispredicted;
      uint8_t branch_type;
    } branch;
  };
};

/// @brief clean representation of all different kinds of records
struct ordered_sample {
  uint16_t type;
  union {
    struct aux_entry aux_entry;
    // struct mmap2_record mmap2_entry;
    struct __attribute__((packed)) {
      struct perf_event_header header;
      uint32_t pid;
      uint32_t tid;
      uint64_t addr;
      uint64_t len;
      uint64_t pgoff;
      union {
        struct {
          uint32_t maj;
          uint32_t min;
          uint64_t ino;
          uint64_t ino_generation;
        };

        struct {
          uint8_t bbuild_id_size;
          uint8_t __reserved_1;
          uint16_t __reserved_2;
          uint8_t build_id[20];
        };
      };

      uint32_t prot;
      uint32_t flags;
      uint64_t file_id;

    } mmap2_entry; // not just mmap2_record because we don't want to keep
                   // dragging around char[]
    struct switch_cpu_wide switch_entry;
    struct process_exit exit_entry;
  } sample;
};

/// @brief reads /proc/cpuinfo to determine if we are using GRV3 or GRV4, and
/// uses exists lat_mem_rd tests to assign cache bins
extern void setup_completion_bins();

/// @brief Takes a raw SPE packet entry and parses into a more manageable format
/// @param record raw data passed in
/// @param entry aux entry to populate
extern void parse_record(struct spe_record *record, struct aux_entry *entry);

/// @brief Conversion function from SPE time scale to Perf time scale
/// @param cyc cycles in SPE time scale
/// @param tc conversion struct (populated during PMU setup)
/// @return perf time
extern uint64_t tsc_to_perf_time(uint64_t cyc, struct perf_tsc_conversion *tc);

/// @brief Utility function to update the B-Tree based on the aux entry
/// provided. Updates the
///        branch or load entries for a given PC based on the aux_entry flags.
/// @param session current CPU session
/// @param entry aux entry to update with
/// @return true if the record was successfully put into the B-Tree, false
/// otherwise
extern bool handle_aux_record(struct cpu_session *session,
                              struct aux_entry *entry);

/// @brief The bulk of the CPU time goes into this. Loops through the aux buffer
/// from the last read
///        tail to the current head. Every aux entry it will upgrade the
///        timestamp, i.e. process the
//         record buffer up to the last entry before this time stamp.
/// @param pmu PMU with the buffer pointers
/// @param session current CPU session
extern void traverse_buffers(struct arm_spe_pmu *pmu,
                             struct cpu_session *session);

/// @brief Iterates through the record buffer, handling MMAP2, EXIT, and
/// SWITCH_CPU_WIDE records as they come
/// @param pmu PMU with the buffer pointers
/// @param session current CPU session
/// @param ts timestamp to upgrade to
extern void upgrade_ts(struct arm_spe_pmu *pmu, struct cpu_session *session,
                       uint64_t ts);

extern struct btree *vm_spe_tr;
extern struct pid_maps_table *mapping_table;

#endif // AUX_TRACE_H_;