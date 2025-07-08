#include <dirent.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btree.h"
#include "config.h"

#define PATH_MAX 512

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

#define PID_MAP_HASH_SIZE 1024
#define INITIAL_SIZE 1024

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
struct __attribute__((packed)) switch_cpu_wide_record {
  struct perf_event_header header;
  uint32_t next_prev_pid;
  uint32_t next_prev_tid;
  struct sample_id sid;
};

/// @brief process_exit spec from
/// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
struct __attribute__((packed)) process_exit_record {
  struct perf_event_header header;
  uint32_t pid, ppid;
  uint32_t tid, ptid;
  uint64_t time;
  struct sample_id sid;
};

/// @brief raw_spe_record spec from observing perf reports and ARM docs
struct __attribute__((packed)) raw_spe_record {
  uint8_t __reserved1;
  uint8_t pc[7];
  uint8_t __reserved2;
  uint8_t __reserved3[10];
  uint8_t type;
  uint8_t reg;
  uint8_t identifier;
  uint32_t events_packet;
  uint8_t __reserved4;
  uint16_t issue_lat;
  uint8_t __reserved5;
  uint16_t total_lat;
  uint64_t vaddr;
  uint8_t __reserved6;
  uint8_t __reserved7;
  uint16_t x_lat;
  uint8_t __reserved8[9];
  uint8_t __reserved9;
  uint8_t data_source;
  uint8_t __reserved10;
  uint64_t timestamp;
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

struct map_entry {
  uint64_t start; // virtual address start
  uint64_t end;   // virtual address end
  uint64_t pgoff; // file offset
  uint32_t filename_index;
};

struct pid_maps {
  struct map_entry *maps;
  size_t count;
  size_t capacity;
  pid_t pid;
  struct pid_maps *next; // for hash collision handling
};

struct pid_maps_table {
  struct pid_maps *buckets[PID_MAP_HASH_SIZE];
};

struct __attribute__((packed)) mmap2_mapping_entry {
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
};

/// @brief clean representation of all different kinds of records
struct unified_buffer_entry {
  uint16_t type;
  union {
    struct aux_entry aux_entry;
    struct mmap2_mapping_entry mmap2_entry;
    struct switch_cpu_wide_record switch_entry;
    struct process_exit_record exit_entry;
  } sample;
};

struct completion_hist {
  uint64_t bin_1, bin_2, bin_3, bin_4;
};

struct vm_spe_btree_entry {
  uint16_t type;
  uint32_t file_id;
  off_t offset;

  uint64_t retired_insts;
  uint64_t total_latency;
  uint64_t issue_latency;
  uint64_t saturated_packets;

  union {
    struct {
      uint64_t x_latency;
      struct completion_hist l1, l2, l3, dram;
    } load_entry;

    struct {
      uint64_t not_taken_branches, mispredicted;
      uint8_t branch_type;
    } branch_entry;
  };
};

/// @brief main function that APerf can invoke to run the tool
/// @param argc size of char array
/// @param argv arguments
/// @return nonzero return indicates error
int hotline_main(int argc, char *argv[]);