#include "fname_binary_map.h"

static const Dwfl_Callbacks callbacks = {
    .find_elf = dwfl_build_id_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .section_address = dwfl_offline_section_address,
};

struct btree *FNAME_BINARY_MAP = NULL;

int fname_binary_map_compare(const void *a, const void *b, void *udata) {
  const fname_binary_map_entry_t *ua = a;
  const fname_binary_map_entry_t *ub = b;

  return strcmp(ua->filename, ub->filename);
}

// Helper function to process ELF sections
bool process_elf_sections(binary_info_t *info) {
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
  return (info->text_section && info->symtab && info->strtab);
}

// Helper function to initialize DWARF debug info
bool init_dwarf_info(binary_info_t *info, const char *filename) {
  info->dwfl = dwfl_begin(&callbacks);
  if (!info->dwfl) {
    fprintf(stderr, "Failed to initialize DWARF reader\n");
    return false;
  }

  dwfl_report_begin(info->dwfl);
  Dwfl_Module *module =
      dwfl_report_elf(info->dwfl, filename, filename, -1, 0, false);
  dwfl_report_end(info->dwfl, NULL, NULL);

  if (!module) {
    fprintf(stderr, "Failed to load debug info\n");
    dwfl_end(info->dwfl);
    return false;
  }

  return true;
}

binary_info_t *load_binary(const char *filename) {
  // Allocate and initialize binary info structure
  binary_info_t *info = calloc(1, sizeof(binary_info_t));
  if (!info) {
    fprintf(stderr, "Failed to allocate memory for binary_info_t\n");
    return NULL;
  }

  // Initialize Capstone
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &info->cs_handle) != CS_ERR_OK) {
    fprintf(stderr, "Failed to initialize Capstone\n");
    goto cleanup_info;
  }

  // Open the binary file
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Non-fatal: Cannot open binary %s\n", filename);
    goto cleanup_capstone;
  }

  // Get file size
  struct stat st;
  if (fstat(fd, &st) < 0) {
    fprintf(stderr, "Failed to get file stats\n");
    goto cleanup_fd;
  }
  info->size = st.st_size;

  // Map file into memory
  info->map = mmap(NULL, info->size, PROT_READ, MAP_PRIVATE, fd, 0);
  ASSERT(info->map != MAP_FAILED, "Failed to mmap binary.");

  // Parse ELF header
  info->ehdr = (Elf64_Ehdr *)info->map;

  // This is a graceful cleanup without an ASSERT because sometimes files like
  // [vdso] and [stack] show up, and we don't want to crash on them.
  if (memcmp(info->ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    fprintf(stderr, "Not an ELF file\n");
    goto cleanup_mmap;
  }

  // Get section headers and string table
  info->shdr = (Elf64_Shdr *)((char *)info->map + info->ehdr->e_shoff);
  info->shstrtab =
      (char *)info->map + info->shdr[info->ehdr->e_shstrndx].sh_offset;

  // These are also graceful cleanups for the same reason. We don't want to
  // crash the whole program for a single file that may not be traceable back
  // with debug info. Find and process important sections
  if (!process_elf_sections(info)) {
    goto cleanup_mmap;
  }

  // Initialize DWARF debug info
  if (!init_dwarf_info(info, filename)) {
    goto cleanup_mmap;
  }

  return info;

  // Cleanup handlers
cleanup_mmap:
  munmap(info->map, info->size);
cleanup_fd:
  close(fd);
cleanup_capstone:
  cs_close(&info->cs_handle);
cleanup_info:
  free(info);
  return NULL;
}

void init_fname_binary_btree() {
  FNAME_BINARY_MAP = btree_new(sizeof(fname_binary_map_entry_t), 0,
                               fname_binary_map_compare, NULL);
  btree_clear(FNAME_BINARY_MAP);
}

binary_info_t *get_fname_binary_map_entry(char *filename) {
  fname_binary_map_entry_t fname_entry;
  fname_entry.filename = filename;

  const fname_binary_map_entry_t *result =
      btree_get(FNAME_BINARY_MAP, &fname_entry);
  if (result == NULL) {  // need to load binary now
    binary_info_t *info = load_binary(filename);
    fname_entry.binary_info = info;
    btree_set(FNAME_BINARY_MAP, &fname_entry);
    return info;
  } else {
    return result->binary_info;  // already loaded previously, just recycle
  }
}

char *get_function_name(binary_info_t *info, uint64_t addr) {
  if (!info || !info->symtab || !info->strtab) return NULL;

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

char *get_assembly(binary_info_t *info, uint64_t offset) {
  char *assembly = NULL;

  // Check if offset is in text section
  if (offset >= info->text_addr && offset < info->text_addr + info->text_size) {
    uint64_t roffset = offset - info->text_addr;
    cs_insn *insn;
    size_t count =
        cs_disasm(info->cs_handle, (uint8_t *)info->text_section + roffset,
                  4,  // Read 4 bytes for instruction
                  offset,
                  1,  // Disassemble 1 instruction
                  &insn);

    if (count > 0) {
      // Allocate and format assembly string
      size_t len = strlen(insn[0].mnemonic) + strlen(insn[0].op_str) + 2;
      assembly = malloc(len);
      if (assembly) {
        int res = snprintf(assembly, len, "%s %s", insn[0].mnemonic, insn[0].op_str);
        ASSERT(res > 0, "snprintf failed.");

        // Replace commas with spaces
        for (char *p = assembly; *p; p++) {
          if (*p == ',') *p = ' ';
        }
      }
      cs_free(insn, count);
    }
  }

  return assembly;
}

char *get_absolute_source_path(const char *binary_path,
                               const char *source_path) {
  if (!source_path) {
    return NULL;
  }

  // If it's already an absolute path, just return a copy
  if (source_path[0] == '/') {
    return strdup(source_path);
  }

  // For relative paths, resolve against the binary's directory
  char *binary_dir = strdup(binary_path);
  char *last_slash = strrchr(binary_dir, '/');
  if (last_slash) {
    *(last_slash + 1) = '\0';  // Cut off the filename, keep the slash
  }

  // Combine paths and resolve
  size_t full_len = strlen(binary_dir) + strlen(source_path) + 1;
  char *combined = malloc(full_len);
  if (!combined) {
    free(binary_dir);
    return NULL;
  }

  int res = snprintf(combined, full_len, "%s%s", binary_dir, source_path);
  ASSERT(res > 0, "snprintf failed.");
  free(binary_dir);

  // Use realpath to resolve the absolute path
  char *absolute = realpath(combined, NULL);
  free(combined);

  return absolute
             ? absolute
             : strdup(source_path);  // Fall back to original if realpath fails
}

source_file_info_t *get_source_info(char *binary_path, binary_info_t *info,
                                    uint64_t addr) {
  if (!info || !info->dwfl) {
    return NULL;
  }

  Dwfl_Module *module = dwfl_addrmodule(info->dwfl, addr);
  if (!module) {
    return NULL;
  }

  Dwfl_Line *line_info = dwfl_getsrc(info->dwfl, addr);
  if (!line_info) {
    return NULL;
  }

  int line_number;
  const char *relative_path =
      dwfl_lineinfo(line_info, NULL, &line_number, NULL, NULL, NULL);
  if (!relative_path) {
    return NULL;
  }

  // Allocate the structure
  source_file_info_t *source_info = malloc(sizeof(source_file_info_t));
  if (!source_info) {
    return NULL;
  }

  // Get absolute path and store line number
  source_info->filename = get_absolute_source_path(binary_path, relative_path);
  if (!source_info->filename) {
    free(source_info);
    return NULL;
  }
  source_info->line_number = line_number;

  return source_info;
}

char *get_line_at_line_number(const char *filename, int target_line) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    return NULL;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  int current_line = 1;

  // Skip to target line
  while (current_line < target_line) {
    read = getline(&line, &len, file);
    if (read == -1) {
      free(line);
      fclose(file);
      return NULL;
    }
    current_line++;
  }

  // Read target line
  read = getline(&line, &len, file);
  fclose(file);

  if (read == -1) {
    free(line);
    return NULL;
  }

  // Remove newline if present
  if (read > 0 && line[read - 1] == '\n') {
    line[read - 1] = '\0';
  }

  // Allocate new string with space for quotes and null terminator
  // Add quotes so that in CSV representation commas are not an issue
  size_t quoted_len = strlen(line) + 3;  // +2 for quotes, +1 for null
  char *quoted_line = malloc(quoted_len);
  if (!quoted_line) {
    free(line);
    return NULL;
  }

  int res = snprintf(quoted_line, quoted_len, "\"%s\"", line);
  ASSERT(res > 0, "snprintf failed.");
  free(line);

  return quoted_line;
}

debug_info_t *get_debug_info(char *filename, uint64_t offset) {
  binary_info_t *info = get_fname_binary_map_entry(filename);
  debug_info_t *dinfo = calloc(1, sizeof(debug_info_t));
  ASSERT(dinfo != NULL, "Failed to create debug info struct.")

  if (info) {
    const source_file_info_t *source = get_source_info(filename, info, offset);
    if (source) {
      dinfo->src_file = strdup(source->filename);
      dinfo->line_num = source->line_number;
      dinfo->line =
          get_line_at_line_number(source->filename, source->line_number);
    } else {
      dinfo->src_file = "???";
      dinfo->line = "???";
      dinfo->line_num = 0;
    }

    const char *function = get_function_name(info, offset);
    if (function) {
      dinfo->function = strdup(function);
    } else {
      dinfo->function = "???";
    }

    const char *assembly = get_assembly(info, offset);
    if (assembly) {
      dinfo->assembly = strdup(assembly);
    } else {
      dinfo->assembly = "???";
    }
  }
  return dinfo;
}

void print_debug_info(const debug_info_t *debug_info) {
  if (!debug_info) {
    printf("No debug info available\n");
    return;
  }

  printf("Source file: %s\n",
         debug_info->src_file ? debug_info->src_file : "(null)");

  if (debug_info->line_num) {
    printf("Line number: %lu\n", debug_info->line_num);
  }

  printf("Source line: %s\n", debug_info->line ? debug_info->line : "(null)");

  printf("Assembly: %s\n",
         debug_info->assembly ? debug_info->assembly : "(null)");

  printf("Function: %s\n",
         debug_info->function ? debug_info->function : "(null)");
}