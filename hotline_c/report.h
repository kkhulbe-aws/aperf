#include <capstone/capstone.h>
#include <dwarf.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAX_LINE 2048
#define MAX_ENTRIES 10000
#define MAX_LINE_LENGTH 256
#define PATH_MAX 512

extern const char *get_hotline_dir();
extern const char *get_hotline_report_dir();

#define REPORT_FILE_PATH(filename)                                             \
  char filepath[MAX_LINE];                                                     \
  snprintf(filepath, sizeof(filepath), "%s/data/%s.csv",                       \
           get_hotline_report_dir(), filename)

#define PROCESS_LIMIT 200
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/// @brief branch entry struct read in from the branch CSV file emitted
typedef struct {
  char filename[256];
  uint64_t offset;
  int retired_insts;
  int not_taken_branches;
  int mispredicted;
  int total_latency;
  int issue_latency;
  int saturated;
  int branch_type;
} branch_entry;

/// @brief memory op. entry struct read in from the memory op. CSV file emitted
typedef struct {
  char filename[256];
  uint64_t offset;
  int retired_insts;
  int total_latency;
  int issue_latency;
  int translation_latency;
  int l1_bins[4];
  int l2_bins[4];
  int l3_bins[4];
  int dram_bins[4];
  int saturated;
} completion_entry;

/// @brief debug data that is emitted in the output
typedef struct {
  char *assembly;
  char *source_file_line;
  char *line;
} debug_info_data;

/// @brief intermediary debug data. This is used for extracting assembly lines
typedef struct {
  csh cs_handle;
  Dwfl *dwfl;
  char *elf_data;
  size_t elf_size;
  uint64_t text_addr;
  uint64_t text_size;
  void *text_section;
} debug_info_metadata;

typedef struct {
  void *map;
  size_t size;
  Elf64_Ehdr *ehdr;
  Elf64_Shdr *shdr;
  char *shstrtab;
  Elf64_Sym *symtab;
  char *strtab;
  int sym_count;
  void *text_section;
  uint64_t text_addr;
  size_t text_size;
  Dwfl *dwfl;
  csh cs_handle; // Capstone handle
} binary_info;

void build_report();