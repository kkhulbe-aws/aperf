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

extern const char *get_hotline_dir();
extern const char *get_hotline_report_dir();

#define REPORT_FILE_PATH(filename)                                             \
  char filepath[MAX_LINE];                                                     \
  snprintf(filepath, sizeof(filepath), "%s/data/%s.csv",                       \
           get_hotline_report_dir(), filename)

#define PROCESS_LIMIT 200
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

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
} BranchEntry;

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
} CompletionEntry;

typedef struct {
  char *assembly;
  char *source_file_line;
} DebugInfo;

typedef struct {
  csh cs_handle;
  Dwfl *dwfl;
  char *elf_data;
  size_t elf_size;
  uint64_t text_addr;
  uint64_t text_size;
  void *text_section;
} DebugInfo_Internal;

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
} BinaryInfo;

static const Dwfl_Callbacks callbacks = {
    .find_elf = dwfl_build_id_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .section_address = dwfl_offline_section_address,
};

static DebugInfo_Internal debug_info = {0};

void unload_binary(BinaryInfo *info) {
  if (!info)
    return;
  cs_close(&info->cs_handle);
  if (info->dwfl)
    dwfl_end(info->dwfl);
  if (info->map)
    munmap(info->map, info->size);
  free(info);
}

BinaryInfo *load_binary(const char *filename) {
  BinaryInfo *info = calloc(1, sizeof(BinaryInfo));
  if (!info) {
    printf("Unable to calloc memroy for BinaryInfo\n");
    exit(EXIT_FAILURE);
  }

  // initialize Capstone
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &info->cs_handle) != CS_ERR_OK) {
    rs_wrapper_error("Failed to initialize Capstone\n");
    free(info);
    exit(EXIT_FAILURE);
    return NULL;
  }

  // open the file
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    cs_close(&info->cs_handle);
    // invalid file binary provided, or in accessible. We should
    // still gracefully continue parsing everything else, rather than
    // failing the report generation.
    printf("nonfatal error. continuing...\n");
    free(info);
    return NULL;
  }

  // get file size
  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    cs_close(&info->cs_handle);
    free(info);
    exit(EXIT_FAILURE);
    return NULL;
  }
  info->size = st.st_size;

  // map file into memory
  info->map = mmap(NULL, info->size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (info->map == MAP_FAILED) {
    perror("mmap");
    close(fd);
    cs_close(&info->cs_handle);
    free(info);
    return NULL;
  }
  close(fd);

  // get ELF header
  info->ehdr = (Elf64_Ehdr *)info->map;
  if (memcmp(info->ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    rs_wrapper_error("Not an ELF file\n");
    goto error;
  }

  // get section headers
  info->shdr = (Elf64_Shdr *)((char *)info->map + info->ehdr->e_shoff);

  // get section header string table
  info->shstrtab =
      (char *)info->map + info->shdr[info->ehdr->e_shstrndx].sh_offset;

  // find important sections
  for (int i = 0; i < info->ehdr->e_shnum; i++) {
    char *section_name = info->shstrtab + info->shdr[i].sh_name;

    if (strcmp(section_name, ".text") == 0) {
      info->text_section = (char *)info->map + info->shdr[i].sh_offset;
      info->text_addr = info->shdr[i].sh_addr;
      info->text_size = info->shdr[i].sh_size;
    } else if (strcmp(section_name, ".symtab") == 0) {
      info->symtab = (Elf64_Sym *)((char *)info->map + info->shdr[i].sh_offset);
      info->sym_count = info->shdr[i].sh_size / sizeof(Elf64_Sym);
    } else if (strcmp(section_name, ".strtab") == 0) {
      info->strtab = (char *)info->map + info->shdr[i].sh_offset;
    }
  }

  // initialize DWARF debug info
  info->dwfl = dwfl_begin(&callbacks);
  if (info->dwfl == NULL) {
    rs_wrapper_error("Failed to initialize DWARF reader\n");
    goto error;
  }

  // load debug info for the binary
  dwfl_report_begin(info->dwfl);
  Dwfl_Module *module =
      dwfl_report_elf(info->dwfl, filename, filename, -1, 0, false);
  dwfl_report_end(info->dwfl, NULL, NULL);

  if (!module) {
    rs_wrapper_error("Failed to load debug info\n");
    goto error;
  }

  return info;

error:
  unload_binary(info);
  exit(EXIT_FAILURE);
  return NULL;
}

void cleanup_debug_info(void) {
  if (debug_info.elf_data != NULL) {
    munmap(debug_info.elf_data, debug_info.elf_size);
  }
  if (debug_info.dwfl != NULL) {
    dwfl_end(debug_info.dwfl);
  }
  cs_close(debug_info.cs_handle);
}

void process_branch_file(const char *filename, BranchEntry *entries,
                         int *count) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    printf("Error opening branch file %s: %s\n", filename, strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  char line[MAX_LINE];
  *count = 0;

  // skip header
  if (fgets(line, sizeof(line), fp) == NULL) {
    fclose(fp);
    return;
  }

  while (fgets(line, sizeof(line), fp) && *count < MAX_ENTRIES) {
    BranchEntry *entry = &entries[*count];
    int result = sscanf(line, "%[^,],%lx,%d,%d,%d,%d,%d,%d,%d", entry->filename,
                        &entry->offset, &entry->retired_insts,
                        &entry->not_taken_branches, &entry->mispredicted,
                        &entry->total_latency, &entry->issue_latency,
                        &entry->saturated, &entry->branch_type);

    if (result == 9) {
      (*count)++;
    }
  }
  fclose(fp);
}

void process_completion_file(const char *filename, CompletionEntry *entries,
                             int *count) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    printf("Error opening completion file %s: %s\n", filename, strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  char line[MAX_LINE];
  *count = 0;

  // skip header
  if (fgets(line, sizeof(line), fp) == NULL) {
    fclose(fp);
    return;
  }

  while (fgets(line, sizeof(line), fp) && *count < MAX_ENTRIES) {
    CompletionEntry *entry = &entries[*count];
    int result = sscanf(
        line,
        "%[^,],%lx,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,"
        "%d",
        entry->filename, &entry->offset, &entry->retired_insts,
        &entry->total_latency, &entry->issue_latency,
        &entry->translation_latency, &entry->l1_bins[0], &entry->l1_bins[1],
        &entry->l1_bins[2], &entry->l1_bins[3], &entry->l2_bins[0],
        &entry->l2_bins[1], &entry->l2_bins[2], &entry->l2_bins[3],
        &entry->l3_bins[0], &entry->l3_bins[1], &entry->l3_bins[2],
        &entry->l3_bins[3], &entry->dram_bins[0], &entry->dram_bins[1],
        &entry->dram_bins[2], &entry->dram_bins[3], &entry->saturated);

    if (result == 23) {
      (*count)++;
    }
  }
  fclose(fp);
}

void get_source_info(BinaryInfo *info, uint64_t addr, char **filename,
                     int *line) {
  *filename = NULL;
  *line = 0;

  Dwfl_Module *module = dwfl_addrmodule(info->dwfl, addr);
  if (!module)
    return;

  Dwfl_Line *line_info = dwfl_getsrc(info->dwfl, addr);
  if (line_info) {
    *filename = strdup(dwfl_lineinfo(line_info, NULL, line, NULL, NULL, NULL));
  }
}

DebugInfo *get_asm(const char *filename, uint64_t offset) {
  BinaryInfo *info = load_binary(filename);
  DebugInfo *dinfo = (DebugInfo *)malloc(sizeof(DebugInfo));
  memset(dinfo, 0, sizeof(DebugInfo));

  char location_with_line[151] = "???";
  char source_line[256] = "???";

  // allocate memory for assembly string
  dinfo->assembly = (char *)malloc(256);
  dinfo->source_file_line = (char *)malloc(256);
  if (!dinfo->assembly || !dinfo->source_file_line) {
    free(dinfo->assembly);
    free(dinfo->source_file_line);
    free(dinfo);
    return NULL;
  }

  snprintf(dinfo->source_file_line, sizeof(dinfo->source_file_line), "%s",
           "???");
  snprintf(dinfo->assembly, sizeof(dinfo->assembly), "%s", "???");

  if (info) {
    // get source file information
    char *source_file;
    int line_number = 0;
    get_source_info(info, offset, &source_file, &line_number);
    if (source_file) {
      snprintf(location_with_line, sizeof(location_with_line), "%s:%d",
               source_file, line_number);

      // get source line
      FILE *f = fopen(source_file, "r");
      if (f) {
        char line[256];
        int current_line = 0;
        while (fgets(line, sizeof(line), f) && current_line < line_number) {
          current_line++;
        }
        if (current_line == line_number) {
          line[strcspn(line, "\n")] = 0;
          strncpy(source_line, line, sizeof(source_line) - 1);
          source_line[sizeof(source_line) - 1] = '\0';
        }
        fclose(f);
      }
      free(source_file);
    } else {
      // if no source file is found, use binary with offset
      snprintf(location_with_line, sizeof(location_with_line), "%s:0x%lx",
               filename, offset);
    }

    strncpy(dinfo->source_file_line, location_with_line, 255);
    dinfo->source_file_line[255] = '\0';

    if (offset >= info->text_addr &&
        offset < info->text_addr + info->text_size) {
      uint64_t roffset = offset - info->text_addr;
      cs_insn *insn;
      size_t count =
          cs_disasm(info->cs_handle, (uint8_t *)info->text_section + roffset, 4,
                    offset, 1, &insn);

      if (count > 0) {
        char temp_assembly[256];
        snprintf(temp_assembly, sizeof(temp_assembly), "%s %s",
                 insn[0].mnemonic, insn[0].op_str);

        // replace commas with spaces
        for (char *p = temp_assembly; *p; p++) {
          if (*p == ',')
            *p = ' ';
        }

        strncpy(dinfo->assembly, temp_assembly, 255);
        dinfo->assembly[255] = '\0';

        cs_free(insn, count);
      }
    }
  }

  return dinfo;
}

char *get_function_name(BinaryInfo *info, uint64_t addr) {
  if (!info || !info->symtab || !info->strtab)
    return NULL;

  for (int i = 0; i < info->sym_count; i++) {
    if (ELF64_ST_TYPE(info->symtab[i].st_info) == STT_FUNC) {
      if (addr >= info->symtab[i].st_value &&
          addr < info->symtab[i].st_value + info->symtab[i].st_size) {
        return strdup(info->strtab + info->symtab[i].st_name);
      }
    }
  }
  return NULL;
}

// comparison function for sorting by execution latency
int compare_exec_latency(const void *a, const void *b) {
  const CompletionEntry *ea = (const CompletionEntry *)a;
  const CompletionEntry *eb = (const CompletionEntry *)b;
  return (eb->total_latency - eb->issue_latency - eb->translation_latency) -
         (ea->total_latency - ea->issue_latency - ea->translation_latency);
}

void generate_exec_latency_view(CompletionEntry *completions,
                                int completion_count) {
  REPORT_FILE_PATH("exec_lat_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    fprintf("Error creating exec_latency_view.csv: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  fprintf(fp, "Avg Exec Latency,Count,Saturated,Location,Function,Assembly\n");

  // sort completions by execution latency
  qsort(completions, completion_count, sizeof(CompletionEntry),
        compare_exec_latency);

  // process completion entries
  // assuming you have a BinaryInfo struct for each file

  // process completion entries
  for (int i = 0; i < MIN(completion_count, PROCESS_LIMIT); i++) {
    BinaryInfo *binary_info = load_binary(completions[i].filename);
    DebugInfo dinfo =
        *(get_asm(completions[i].filename, completions[i].offset));

    // get function name
    char *function_name = get_function_name(binary_info, completions[i].offset);

    fprintf(fp, "%.2f,%d,%d,%s,%s,%s\n",
            (double)(completions[i].total_latency -
                     completions[i].issue_latency -
                     completions[i].translation_latency) /
                completions[i].retired_insts,
            completions[i].retired_insts, completions[i].saturated,
            dinfo.source_file_line, function_name ? function_name : "???",
            dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!function_name)
      free(function_name);

    unload_binary(binary_info);
  }

  fclose(fp);
}

// comparison function for sorting by execution latency
int compare_issue_latency(const void *a, const void *b) {
  const CompletionEntry *ea = (const CompletionEntry *)a;
  const CompletionEntry *eb = (const CompletionEntry *)b;
  return (eb->issue_latency) - (ea->issue_latency);
}

void generate_issue_latency_view(CompletionEntry *completions,
                                 int completion_count) {
  REPORT_FILE_PATH("issue_lat_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    printf("Error creating issue_latency_view.csv: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  fprintf(fp, "Avg Issue Latency,Count,Saturated,Location,Function,Assembly\n");

  // sort completions by execution latency
  qsort(completions, completion_count, sizeof(CompletionEntry),
        compare_issue_latency);

  // process completion entries
  for (int i = 0; i < MIN(completion_count, PROCESS_LIMIT); i++) {
    BinaryInfo *binary_info = load_binary(completions[i].filename);
    DebugInfo dinfo =
        *(get_asm(completions[i].filename, completions[i].offset));

    // get function name
    char *function_name = get_function_name(binary_info, completions[i].offset);

    fprintf(fp, "%.2f,%d,%d,%s,%s,%s\n",
            (double)(completions[i].issue_latency) /
                completions[i].retired_insts,
            completions[i].retired_insts, completions[i].saturated,
            dinfo.source_file_line, function_name ? function_name : "???",
            dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!function_name)
      free(function_name);
    unload_binary(binary_info);
  }

  fclose(fp);
}

// comparison function for sorting by execution latency
int compare_x_latency(const void *a, const void *b) {
  const CompletionEntry *ea = (const CompletionEntry *)a;
  const CompletionEntry *eb = (const CompletionEntry *)b;
  return (eb->translation_latency) - (ea->translation_latency);
}

void generate_x_latency_view(CompletionEntry *completions,
                             int completion_count) {
  REPORT_FILE_PATH("x_lat_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    printf("Error creating x_lat_view.csv: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  fprintf(fp, "Avg X Latency,Count,Saturated,Location,Function,Assembly\n");

  // sort completions by execution latency
  qsort(completions, completion_count, sizeof(CompletionEntry),
        compare_x_latency);

  // process completion entries
  for (int i = 0; i < MIN(completion_count, PROCESS_LIMIT); i++) {
    BinaryInfo *binary_info = load_binary(completions[i].filename);
    DebugInfo dinfo =
        *(get_asm(completions[i].filename, completions[i].offset));

    // get function name
    char *function_name = get_function_name(binary_info, completions[i].offset);

    fprintf(fp, "%.2f,%d,%d,%s,%s,%s\n",
            (double)(completions[i].translation_latency) /
                completions[i].retired_insts,
            completions[i].retired_insts, completions[i].saturated,
            dinfo.source_file_line, function_name ? function_name : "???",
            dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!function_name)
      free(function_name);
    unload_binary(binary_info);
  }

  fclose(fp);
}

// comparison function for sorting by execution latency
int compare_branch(const void *a, const void *b) {
  const BranchEntry *ea = (const BranchEntry *)a;
  const BranchEntry *eb = (const BranchEntry *)b;
  return (eb->total_latency) - (ea->total_latency);
}
void generate_branch_view(BranchEntry *entries, int count) {
  REPORT_FILE_PATH("branch_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    printf("Error creating branch_view.csv: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  fprintf(fp, "Type,Count,Avg_Total_Lat,Avg_Issue_Lat,Not_Taken,Mispredicted,"
              "Saturated,Location,Function,Assembly\n");

  qsort(entries, count, sizeof(BranchEntry), compare_branch);

  for (int i = 0; i < MIN(count, PROCESS_LIMIT); i++) {
    BinaryInfo *binary_info = load_binary(entries[i].filename);
    DebugInfo dinfo = *(get_asm(entries[i].filename, entries[i].offset));

    // get function name
    char *function_name = get_function_name(binary_info, entries[i].offset);

    fprintf(fp, "%s,%d,%.2f,%.2f,%d,%d,%d,%s,%s,%s\n",
            entries[i].branch_type == 0x01 ? "COND" : "IND",
            entries[i].retired_insts,
            ((double)entries[i].total_latency / entries[i].retired_insts),
            ((double)entries[i].issue_latency / entries[i].retired_insts),
            entries[i].not_taken_branches, entries[i].mispredicted,
            entries[i].saturated, dinfo.source_file_line,
            function_name ? function_name : "???", dinfo.assembly);
    unload_binary(binary_info);
  }

  fclose(fp);
}

void generate_completion_view(CompletionEntry *entries, int count) {
  REPORT_FILE_PATH("completion_node_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp)
    return;

  qsort(entries, count, sizeof(CompletionEntry), compare_exec_latency);

  fprintf(
      fp,
      "L1 (%),L1 bins (%% | %% | %% | %%),L2 (%),L2 bins (%% | %% | %% | %%),"
      "L3 (%),L3 bins (%% | %% | %% | %%),DRAM (%),DRAM bins (%% | %% | %% | "
      "%%),"
      "Location,Function,Assembly\n");

  for (int i = 0; i < MIN(count, PROCESS_LIMIT); i++) {
    BinaryInfo *binary_info = load_binary(entries[i].filename);
    DebugInfo dinfo = *(get_asm(entries[i].filename, entries[i].offset));

    char *function_name = get_function_name(binary_info, entries[i].offset);

    int l1_total = entries[i].l1_bins[0] + entries[i].l1_bins[1] +
                   entries[i].l1_bins[2] + entries[i].l1_bins[3];
    int l2_total = entries[i].l2_bins[0] + entries[i].l2_bins[1] +
                   entries[i].l2_bins[2] + entries[i].l2_bins[3];
    int l3_total = entries[i].l3_bins[0] + entries[i].l3_bins[1] +
                   entries[i].l3_bins[2] + entries[i].l3_bins[3];
    int dram_total = entries[i].dram_bins[0] + entries[i].dram_bins[1] +
                     entries[i].dram_bins[2] + entries[i].dram_bins[3];

    int grand_total = l1_total + l2_total + l3_total + dram_total;

    if (grand_total == 0) {
      grand_total = 1; // this will result in 0% for all categories
    }

    double l1_percent = (double)l1_total / grand_total * 100.0;
    double l2_percent = (double)l2_total / grand_total * 100.0;
    double l3_percent = (double)l3_total / grand_total * 100.0;
    double dram_percent = (double)dram_total / grand_total * 100.0;

    // calculate bin percentages
    double l1_bin_percents[4], l2_bin_percents[4], l3_bin_percents[4],
        dram_bin_percents[4];

    for (int j = 0; j < 4; j++) {
      l1_bin_percents[j] =
          l1_total > 0 ? (double)entries[i].l1_bins[j] / l1_total * 100.0 : 0.0;
      l2_bin_percents[j] =
          l2_total > 0 ? (double)entries[i].l2_bins[j] / l2_total * 100.0 : 0.0;
      l3_bin_percents[j] =
          l3_total > 0 ? (double)entries[i].l3_bins[j] / l3_total * 100.0 : 0.0;
      dram_bin_percents[j] =
          dram_total > 0 ? (double)entries[i].dram_bins[j] / dram_total * 100.0
                         : 0.0;
    }

    fprintf(fp,
            "%.2f,%.2f | %.2f | %.2f | %.2f,%.2f,%.2f | %.2f | %.2f | "
            "%.2f,%.2f,%.2f | %.2f | %.2f | %.2f,%.2f,%.2f | %.2f | %.2f | "
            "%.2f,%s,%s,%s\n",
            l1_percent, l1_bin_percents[0], l1_bin_percents[1],
            l1_bin_percents[2], l1_bin_percents[3], l2_percent,
            l2_bin_percents[0], l2_bin_percents[1], l2_bin_percents[2],
            l2_bin_percents[3], l3_percent, l3_bin_percents[0],
            l3_bin_percents[1], l3_bin_percents[2], l3_bin_percents[3],
            dram_percent, dram_bin_percents[0], dram_bin_percents[1],
            dram_bin_percents[2], dram_bin_percents[3], dinfo.source_file_line,
            function_name ? function_name : "???", dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!function_name)
      free(function_name);
    unload_binary(binary_info);
  }

  fclose(fp);
}

int build_report() {
  BranchEntry branch_entries[MAX_ENTRIES];
  CompletionEntry completion_entries[MAX_ENTRIES];
  int branch_count = 0, completion_count = 0;

  const char *report_dir = get_hotline_dir();
  if (report_dir == NULL) {
    rs_wrapper_error("Failed to get hotline report directory\n");
    return 1;
  }

  char branch_file_path[MAX_LINE];
  char completion_file_path[MAX_LINE];

  snprintf(branch_file_path, sizeof(branch_file_path),
           "%s/spe_hotline_branches.bin", report_dir);
  snprintf(completion_file_path, sizeof(completion_file_path),
           "%s/spe_hotline_loads.bin", report_dir);

  // process input files
  process_branch_file(branch_file_path, branch_entries, &branch_count);

  process_completion_file(completion_file_path, completion_entries,
                          &completion_count);

  // generate views
  generate_exec_latency_view(completion_entries, completion_count);
  generate_issue_latency_view(completion_entries, completion_count);
  generate_x_latency_view(completion_entries, completion_count);
  generate_branch_view(branch_entries, branch_count);
  generate_completion_view(completion_entries, completion_count);

  return 0;
}
