#ifndef MMAP_TABLE_H
#define MMAP_TABLE_H

#include "config.h"
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define PID_MAP_HASH_SIZE 1024

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

struct __attribute__((packed)) mmap2_mapping {
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

/// @brief Sets up, frees, and accesses pid tables
extern struct pid_maps_table *create_pid_maps_table(void);
extern void free_pid_maps_table(struct pid_maps_table *table);
extern struct pid_maps *get_pid_maps(struct pid_maps_table *table, pid_t pid);

/// @brief Adds a new pid entry for a given pid
/// @param table global PID table to add into
/// @param pid PID to add into (hashed into an array)
/// @param entry entry to update mapping
extern void add_map_entry(struct pid_maps_table *table, pid_t pid,
                          struct map_entry *entry);

/// @brief Removes all mappings for a given PID. Used for EXIT records.
/// @param table global PID table to add into
/// @param pid PID to add into (hashed into an array)
extern void remove_pid_maps(struct pid_maps_table *table, pid_t pid);

/// @brief Initializes datastructures
extern struct pid_maps_table *init_pid_maps(void);

/// @brief Logic to update the PID table given a new MMAP2 record
/// @param table Table to update
/// @param record MMAP2 record, read from the record buffer during
/// `traverse_buffers`
extern void handle_mmap2_record(struct pid_maps_table *table,
                                const struct mmap2_mapping *record);

/// @brief We are not given MMAP2 records for already running processes. We
/// figure this out by
///        reading /proc/... to get all active processes and map them in.
/// @param table Table to map into
extern void get_initial_mappings(struct pid_maps_table *table);

/// @brief Converts a given progarm counter to a filename and offset
/// @param maps PID datastructure associated with a PID
/// @param pc PC to translate
/// @param filename filename pointer to populate
/// @param file_offset file offset pointer to populate
/// @return 0 if no mapping found, 1 if successfully mapped
extern int pc_to_file_offset(struct pid_maps *maps, uint64_t pc,
                             char **filename, uint64_t *file_offset);

/// @brief We maintain a global filestructure, since many processes can map to
/// the same file. This
///        function allows adding into it
/// @param filename filename to add into it
/// @return returns index at which file was added
extern size_t add_global_filename(const char *filename);

/// @brief Frees all the PID datastructures for a given PID
/// @param table table to clear up
/// @param pid PID to free
extern void free_pid_maps(struct pid_maps_table *table, pid_t pid);

/// @brief Helpful utilitity to figure out the total size of the table
/// @param table input table
/// @return size of the table
extern size_t get_pid_maps_table_size(struct pid_maps_table *table);

extern char *global_filenames[MAX_FILENAMES];
extern size_t global_filename_count;
#endif