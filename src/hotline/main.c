#include "log.h"
#include "sys.h"
#include "config.h"
#include "hotline.h"
#include "fname_map.h"
#include "lat_map.h"
#include "bmiss_map.h"
#include "report.h"

// int main(int argc, char *argv[]) {
//     // init_fname_binary_btree();
//     // uint64_t count;
//     // bmiss_map_entry_t *b_entries = process_bmiss_map_entries("/home/ubuntu/data/hotline_bmiss_map.bin", &count);
//     // // print_bmiss_entries(entries, count);
//     // generate_bmiss_report("/home/ubuntu/report/hotline_bmiss_map_report.bin", b_entries, count);

//     // lat_map_entry_t *l_entries = process_lat_map_entries("/home/ubuntu/data/hotline_lat_map.bin", &count);
//     // printf("ENTRIES: %lu\n", count);
//     // generate_lat_report("/home/ubuntu/report", l_entries, count);
//     build_report(argc, argv);
//     return 0;
// }