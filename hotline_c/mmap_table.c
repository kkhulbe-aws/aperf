#include "mmap_table.h"

/**
 * General purpose functions to manage the MMAP entries
 * - Allows inserting into the table by PID
 * - Each PID table contains subtables of start and end virtual addresses
 * - This allows accurately getting a file offset from SPE virtual address
 * - Allows removing tables by PID
 */

size_t add_global_filename(const char *filename) {
  for (size_t i = 0; i < global_filename_count; i++) {
    if (strcmp(global_filenames[i], filename) == 0) {
      return i;
    }
  }
  if (global_filename_count < MAX_FILENAMES) {
    global_filenames[global_filename_count] = strdup(filename);
    return global_filename_count++;
  }
  return (size_t)-1;
}

struct pid_maps_table *init_pid_maps() {
  struct pid_maps_table *table = calloc(1, sizeof(struct pid_maps_table));
  if (!table) {
    rs_wrapper_error("Failed allocation of pid_maps_table. Exiting.\n");
    exit(EXIT_FAILURE);
  }
  return table;
}

struct pid_maps *get_pid_maps(struct pid_maps_table *table, pid_t pid) {
  uint32_t hash = ((uint32_t)pid) % PID_MAP_HASH_SIZE;
  struct pid_maps *maps = table->buckets[hash];

  while (maps) {
    if (maps->pid == pid)
      return maps;
    maps = maps->next;
  }

  maps = calloc(1, sizeof(struct pid_maps));
  maps->pid = pid;
  maps->capacity = 16;
  maps->maps = malloc(maps->capacity * sizeof(struct map_entry));
  if (!maps->maps) {
    rs_wrapper_error("allocating maps for pid %lu failed\n", pid);
    exit(EXIT_FAILURE);
  }
  maps->next = table->buckets[hash];
  table->buckets[hash] = maps;

  return maps;
}

void handle_mmap2_record(struct pid_maps_table *table,
                         const struct mmap2_mapping *record) {
  struct pid_maps *maps = get_pid_maps(table, record->pid);

  if (maps->count >= maps->capacity) {
    maps->capacity *= 2;
    maps->maps = realloc(maps->maps, maps->capacity * sizeof(struct map_entry));

    if (!maps->maps) {
      rs_wrapper_error("reallocating maps failed\n");
      exit(EXIT_FAILURE);
    }
  }

  struct map_entry *entry = &maps->maps[maps->count];

  entry->start = record->addr;
  entry->end = record->addr + record->len;
  entry->pgoff = record->pgoff;
  entry->filename_index = record->file_id;

  maps->count++;
}

int pc_to_file_offset(struct pid_maps *maps, uint64_t pc, char **filename,
                      uint64_t *file_offset) {
  for (size_t i = 0; i < maps->count; i++) {
    if (pc >= maps->maps[i].start && pc < maps->maps[i].end) {
      *filename = global_filenames[maps->maps[i].filename_index];
      *file_offset = pc - maps->maps[i].start + maps->maps[i].pgoff;
      return 1;
    }
  }
  return 0;
}

void free_pid_maps_table(struct pid_maps_table *table) {
  for (int i = 0; i < PID_MAP_HASH_SIZE; i++) {
    struct pid_maps *maps = table->buckets[i];
    while (maps) {
      struct pid_maps *next = maps->next;
      free(maps->maps);
      free(maps);
      maps = next;
    }
  }
  free(table);

  // Free global filenames
  for (size_t i = 0; i < global_filename_count; i++) {
    free(global_filenames[i]);
  }
}

void free_pid_maps(struct pid_maps_table *table, pid_t pid) {
  if (!table)
    return;

  uint32_t hash = ((uint32_t)pid) % PID_MAP_HASH_SIZE;
  struct pid_maps *maps = table->buckets[hash];
  struct pid_maps *prev = NULL;

  while (maps) {
    if (maps->pid == pid) {
      // found the pid to remove
      if (prev) {
        // if not first in bucket, update previous node's next pointer
        prev->next = maps->next;
      } else {
        // if first in bucket, update bucket head
        table->buckets[hash] = maps->next;
      }

      // free the maps array and the pid_maps structure
      free(maps->maps);
      free(maps);
      return;
    }
    prev = maps;
    maps = maps->next;
  }
}

void get_initial_mappings(struct pid_maps_table *table) {
  DIR *proc_dir;
  struct dirent *pid_entry;

  proc_dir = opendir("/proc");
  if (!proc_dir)
    return;

  while ((pid_entry = readdir(proc_dir))) {
    if (!isdigit(pid_entry->d_name[0]))
      continue;

    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%.230s/maps",
             pid_entry->d_name);

    FILE *maps = fopen(maps_path, "r");
    if (!maps)
      continue;

    pid_t pid = atoi(pid_entry->d_name);
    char line[1024];

    while (fgets(line, sizeof(line), maps)) {
      unsigned long start, end;
      unsigned long offset;
      char perms[5];
      char path[256] = "";

      sscanf(line, "%lx-%lx %4s %lx %*x:%*x %*u %255s", &start, &end, perms,
             &offset, path);

      if (path[0]) {
        struct mmap2_mapping record = {
            .pid = pid, .addr = start, .len = end - start, .pgoff = offset};
        record.file_id = add_global_filename(path);

        handle_mmap2_record(table, &record);
      }
    }

    fclose(maps);
  }

  closedir(proc_dir);
}

// @deprecated
size_t get_pid_maps_table_size(struct pid_maps_table *table) {
  if (!table)
    return 0;

  size_t total_size = sizeof(struct pid_maps_table);

  for (int i = 0; i < PID_MAP_HASH_SIZE; i++) {
    struct pid_maps *maps = table->buckets[i];
    while (maps) {
      total_size += sizeof(struct pid_maps);
      total_size += maps->capacity * sizeof(struct map_entry);
      maps = maps->next;
    }
  }

  // include size of global filenames
  for (size_t i = 0; i < global_filename_count; i++) {
    total_size += strlen(global_filenames[i]) + 1; // +1 for null terminator
  }
  total_size +=
      sizeof(char *) * MAX_FILENAMES; // size of global_filenames array

  return total_size;
}
