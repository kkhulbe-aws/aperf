#include "fname_map.h"

#include <stdio.h>

struct btree *FNAME_MAP = NULL;
const filename_entry_t *cached_entry[CACHE_DEPTH] = {NULL};

/// @brief B-Tree compare function for FNAME_MAP structs
/// @param a First entry to compare
/// @param b Second entry to compare
/// @param udata Unused
/// @return 1 if a > b, -1 if a < b, 0 if a = b
int fname_compare(const void *a, const void *b, void *udata) {
  const filename_entry_t *ua = a;
  const filename_entry_t *ub = b;

  if (ua->pid < ub->pid) return -1;
  if (ua->pid > ub->pid) return 1;

  return 0;
}

/// @brief Perf does not emit MMAP2 records for already running processes.
/// We will read through /proc/.../maps and get the virtual address mappings.
void insert_initial_mappings() {
  DIR *proc_dir;
  struct dirent *pid_entry;

  proc_dir = opendir("/proc");
  ASSERT(proc_dir != NULL, "Unable to open /proc.");

  while ((pid_entry = readdir(proc_dir))) {
    if (!isdigit(pid_entry->d_name[0])) continue;

    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%.230s/maps",
             pid_entry->d_name);

    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) continue;

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
        size_t filename_len = strlen(path);
        size_t total_size = sizeof(mmap2_record_t) + filename_len + 1;

        // Allocate continuous memory for record + filename
        mmap2_record_t *record = malloc(total_size);
        memset(record, 0, total_size);

        record->header.type = PERF_RECORD_MMAP2;
        record->header.size = total_size;
        record->pid = pid;
        record->addr = start;
        record->len = end - start;
        record->pgoff = offset;

        // Now copy filename to the space after the record
        memcpy(record->filename, path, filename_len + 1);

        finode_t finode;
        get_file_info(record->filename, &finode);
        record->ino = finode.ino;
        record->maj = finode.maj;
        record->min = finode.min;
        record->ino_generation = finode.ino_generation;

        insert_finode_entry(record);
        insert_fname_entry(record);

        free(record);
      }
    }
  }
}

/// @brief Initializes FNAME_MAP data structures
void init_fname_map() {
  FNAME_MAP = btree_new(sizeof(filename_entry_t), 0, fname_compare, NULL);
  btree_clear(FNAME_MAP);

  insert_initial_mappings();
}

/// @brief Inserts a new MMAP2 record into FNAME_MAP.
/// @param record Record to insert
void insert_fname_entry(mmap2_record_t *record) {
  filename_entry_t key = {.pid = record->pid};

  const filename_entry_t *entry = btree_get(FNAME_MAP, &key);

  // If the key does not exist (NULL), set up a new key, and allocate a new
  // vector for the MMAP data
  if (entry == NULL) {
    filename_entry_t new_entry;
    new_entry.pid = record->pid;

    new_entry.virtual_address_map = vector_create();

    btree_set(FNAME_MAP, &new_entry);
  }

  // After that, when it is guaranteed an entry exists, extract it
  // and insert the new offset mapping into the vector

  entry = btree_get(FNAME_MAP, &key);
  pid_virtual_map_entry_t **virtual_address_map = entry->virtual_address_map;
  // char *filename = strdup(record->filename);

  pid_virtual_map_entry_t *virtual_entry =
      malloc(sizeof(pid_virtual_map_entry_t));
  virtual_entry->start = record->addr;
  virtual_entry->end = record->addr + record->len;
  virtual_entry->pgoff = record->pgoff;
  virtual_entry->finode.ino = record->ino;
  virtual_entry->finode.maj = record->maj;
  virtual_entry->finode.min = record->min;
  virtual_entry->finode.ino_generation = record->ino_generation;

  // Add the value directly to the vector
  vector_add(&entry->virtual_address_map, virtual_entry);
}

void free_filename_entry(filename_entry_t *entry_to_remove) {
  pid_virtual_map_entry_t **vmap = entry_to_remove->virtual_address_map;
  uint64_t vmap_size = vector_size(vmap);

  for (int j = 0; j < vmap_size; j++) {
    pid_virtual_map_entry_t *ventry = ((pid_virtual_map_entry_t **)vmap)[j];
    free(ventry);
  }

  vector_free(entry_to_remove->virtual_address_map);
  btree_delete(FNAME_MAP, entry_to_remove);
}

/// @brief Returns a cached entry or NULL if it doesn't exist.
/// @param entry PID to find
const filename_entry_t *get_filename_cached_entry(pid_t pid) {
  // if (cached_entry && cached_entry->pid == pid) return cached_entry;
  for (int i = 0; i < CACHE_DEPTH; i++) {
    if (cached_entry[i] && cached_entry[i]->pid == pid) return cached_entry[i];
  }
  return NULL;
}

/// @brief Updates the cache with a new entry
/// @param entry Entry to updated
void update_filename_cached_entry(const filename_entry_t *entry) {
  // Shift all entries down, discarding the oldest entry
  for (int i = CACHE_DEPTH - 1; i > 0; i--) {
    cached_entry[i] = cached_entry[i - 1];
  }

  // Put new entry at the front of the cache
  cached_entry[0] = entry;
}

void prune_filename_cache(pid_t pid) {
  for (int i = 0; i < CACHE_DEPTH; i++) {
    if (cached_entry[i] && cached_entry[i]->pid == pid) {
      cached_entry[i] = NULL;
    }
  }
}

/// @brief Removes all virtual offset mappings associated with a PID.
/// @param pid PID to remove mappings for
void remove_fname_entry(pid_t pid) {
  filename_entry_t *entry =
      (filename_entry_t *)btree_get(FNAME_MAP, &(filename_entry_t){.pid = pid});
  if (entry != NULL) {
    free_filename_entry(entry);
    prune_filename_cache(pid);
  }
}

/// @brief Converts an instruction pointer (program counter) into a filename and
/// file offset, given
///        the present active PID for the session.
/// @param pc PC to convert
/// @param pid Active PID
/// @param filename Passed in to populate filename
/// @param offset Passed in to populate file offset
/// @return -1 on failure to map, 0 on success
int va_to_file_offset(uint64_t pc, pid_t pid, finode_t *finode,
                      uint64_t *offset) {
  const filename_entry_t *entry = get_filename_cached_entry(pid);
  if (entry == NULL)
    entry = btree_get(FNAME_MAP, &(filename_entry_t){.pid = pid});

  if (entry == NULL || entry->pid != pid) return -1;

  update_filename_cached_entry(entry);

  pid_virtual_map_entry_t **vmap = entry->virtual_address_map;
  uint64_t vmap_size = vector_size(vmap);

  for (size_t i = 0; i < vmap_size; i++) {
    pid_virtual_map_entry_t *ventry = ((pid_virtual_map_entry_t **)vmap)[i];

    if (pc >= ventry->start && pc < ventry->end) {
      finode->ino = ventry->finode.ino;
      finode->maj = ventry->finode.maj;
      finode->min = ventry->finode.min;
      finode->ino_generation = ventry->finode.ino_generation;

      *offset = pc - ventry->start + ventry->pgoff;

      return 0;
    }
  }

  return -1;
}