/**
 * @file fname_map.h
 * @brief B-Tree modifiers for the filename map and mmap mappings
 * @author Kaustubh Khulbe
 * @ingroup Graviton Software
 */

#ifndef FNAME_MAP_H_
#define FNAME_MAP_H_

#include <dirent.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "btree.h"
#include "log.h"
#include "perf_packets.h"
#include "vec.h"

#define MAX_FILENAME_LENGTH 256

/// @brief Virtual address start and end for each MMAP2 record. Will be stored
/// within a B-Tree.
typedef struct pid_virtual_map_entry {
  uint64_t start;  // virtual address start
  uint64_t end;    // virtual address end
  uint64_t pgoff;  // file offset
} pid_virtual_map_entry_t;

/// @brief For each filename and pid pair, we will store an array of all the
/// mappings associated with it.
typedef struct filename_entry {
  pid_t pid;
  char *filename;
  pid_virtual_map_entry_t **virtual_address_map;  // array of pointers
} filename_entry_t;

/// @brief Inserts a new MMAP2 record into FNAME_MAP.
/// @param record Record to insert
void insert_fname_entry(mmap2_record_t *record);

/// @brief Removes all virtual offset mappings associated with a PID.
/// @param pid PID to remove mappings for
void remove_fname_entry(pid_t pid);

/// @brief Initializes FNAME_MAP data structures
void init_fname_map();

/// @brief Converts an instruction pointer (program counter) into a filename and
/// file offset, given
///        the present active PID for the session.
/// @param pc PC to convert
/// @param pid Active PID
/// @param filename Passed in to populate filename
/// @param offset Passed in to populate file offset
/// @return -1 on failure to map, 0 on success
int pc_to_file_offset(uint64_t pc, pid_t pid, char **filename,
                      uint64_t *offset);

/// @brief Exposed B-Tree structure for all file mappings
extern struct btree *FNAME_MAP;

#endif  // FNAME_MAP_H_