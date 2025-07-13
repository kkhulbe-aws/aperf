/**
 * @file report.h
 * @brief Offline report generation for converting from filenames and offsets to
 * asm/C code.
 * @author Kaustubh Khulbe
 * @ingroup Graviton Software
 */

#ifndef REPORT_H_
#define REPORT_H_

#include "bmiss_map.h"
#include "btree.h"
#include "config.h"
#include "fname_binary_map.h"
#include "lat_map.h"
#include "log.h"

bmiss_map_entry_t *process_bmiss_map_entries(const char *filename,
                                             uint64_t *out_count);
void generate_bmiss_report(char *filepath, bmiss_map_entry_t *entries,
                           uint64_t count);

lat_map_entry_t *process_lat_map_entries(const char *filename,
                                         uint64_t *out_count);

void generate_lat_report(char *filepath, lat_map_entry_t *entries,
                         uint64_t count);

int deserialize_maps(int argc, char *argv[]);
#endif  // REPORT_H_