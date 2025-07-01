#ifndef VM_SPE_BTREE_H_
#define VM_SPE_BTREE_H_

#include "auxtrace.h"
#include <stdbool.h>

struct completion_hist
{
    uint64_t bin_1, bin_2, bin_3, bin_4;
};

struct vm_spe_btree_entry
{
    uint16_t type;
    uint32_t file_id;
    off_t offset;

    uint64_t retired_insts;
    uint64_t total_latency;
    uint64_t issue_latency;
    uint64_t saturated_packets;

    union
    {
        struct
        {
            uint64_t x_latency;
            struct completion_hist l1, l2, l3, dram;
        } load_entry;

        struct
        {
            uint64_t not_taken_branches, mispredicted;
            uint8_t branch_type;
        } branch_entry;
    };
};

/// @brief Compare function to make B-Tree operations possible
/// @param a first node to compare
/// @param b second node to compare
/// @param data auxiliary data (unused)
/// @return -1 if a < b, 1 if a > b, 0 if a == b
extern int vm_spe_btree_compare(const void *a, const void *b, void *data);

/// @brief Iterator for the B-Tree. Used when committing to files. Always returns true for
//         end-to-end iteration.
/// @param node (unused)
/// @param data (unused)
/// @return true
extern bool vm_spe_btree_iter(const void *node, const void *data);
#endif // VM_SPE_BTREE_H_;