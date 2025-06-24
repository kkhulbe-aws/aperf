#ifndef MMAP_TABLE_H
#define MMAP_TABLE_H

#include <err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/perf_event.h>
#include <dirent.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PID_MAP_HASH_SIZE 1024

#define MAX_FILENAMES 2000

struct map_entry
{
    uint64_t start; // virtual address start
    uint64_t end;   // virtual address end
    uint64_t pgoff; // file offset
    uint32_t filename_index;
};

struct pid_maps
{
    struct map_entry *maps;
    size_t count;
    size_t capacity;
    pid_t pid;
    struct pid_maps *next; // for hash collision handling
};

struct pid_maps_table
{
    struct pid_maps *buckets[PID_MAP_HASH_SIZE];
};

struct __attribute__((packed)) mmap2_mapping
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
};

extern struct pid_maps_table *create_pid_maps_table(void);
extern void free_pid_maps_table(struct pid_maps_table *table);
extern struct pid_maps *get_pid_maps(struct pid_maps_table *table, pid_t pid);
extern void add_map_entry(struct pid_maps_table *table, pid_t pid, struct map_entry *entry);
extern void remove_pid_maps(struct pid_maps_table *table, pid_t pid);
extern struct pid_maps_table *init_pid_maps(void);
extern void handle_mmap2_record(struct pid_maps_table *table, const struct mmap2_mapping *record);
extern void print_mapping_table(struct pid_maps_table *table);
extern void get_initial_mappings(struct pid_maps_table *table);
extern int pc_to_file_offset(struct pid_maps *maps, uint64_t pc, char **filename, uint64_t *file_offset);
extern size_t add_global_filename(const char *filename);
extern void free_pid_maps(struct pid_maps_table *table, pid_t pid);
extern size_t get_pid_maps_table_size(struct pid_maps_table *table);

extern char *global_filenames[MAX_FILENAMES];
extern size_t global_filename_count;
#endif