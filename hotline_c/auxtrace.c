#include "auxtrace.h"
#include "vm_spe_btree.h"

// main loop for processing the *record buffer*
// this contains context switch, mmap2, and exit records
// it also contains aux records, but we choose to process that separately all in one go
extern long process_record_buffer(struct arm_spe_pmu *pmu, struct spe_stats *stats, struct cpu_session *session, uint32_t num_cpu, uint32_t spe_period, uint8_t should_throttle)
{
    char *data_page = ((char *)pmu->meta_page) + PAGE_SIZE;
    uint64_t data_head = pmu->meta_page->data_head;
    uint64_t data_tail = pmu->meta_page->data_tail;
    uint64_t data_size = pmu->meta_page->data_size;
    uint64_t sz = 0;


    uint64_t throttle_entries = (THROTTLE_LIMIT / num_cpu) * spe_period / 1000; // e.g., if we are sampling every half a second, we throttle at 
                                                    // half the amount so the average consumption remains under the THROTTLE_LIMIT
    uint64_t processed = 0;

    while (data_tail < data_head)
    {
        if (processed >= throttle_entries && should_throttle) break;
        struct perf_event_header *header = (struct perf_event_header *)(data_page + (data_tail % data_size));
        struct ordered_sample *os;
        uint64_t *key;

        // general process is generate a key (from the timestamp) and the packet
        // and insert into ordered queue (min heap)
        switch (header->type)
        {
        case PERF_RECORD_AUX:
            // indicates that AUX data is ready at a given offset and size
            stats->aux_events++;
            break;
        case PERF_RECORD_MMAP2:
        {
            // new process has been loaded into memory, so we should incorporate it into our mappings
            struct mmap2_record *mmap2_rec = (struct mmap2_record *)header;

            // calculate the filename length: header->size contains total size of the record
            // subtract the size of the fixed portion of mmap2_record to get filename length
            size_t fixed_size = offsetof(struct mmap2_record, filename);
            size_t filename_len = header->size - fixed_size - sizeof(struct sample_id);

            // allocate space for the entire record including variable length filename
            os = (struct ordered_sample *)malloc(sizeof(struct ordered_sample));
            key = (uint64_t *)malloc(sizeof(uint64_t));

            if (os == NULL || key == NULL)
            {
                fprintf(stderr, "Memory allocation failed\n");
                break;
            }

            // copy the fixed portion first
            memcpy(&(os->sample.mmap2_entry), mmap2_rec, fixed_size);

            struct sample_id *sid = (struct sample_id *)(((char *)mmap2_rec) + fixed_size + filename_len);
            *key = sid->time;

            if (filename_len > 0)
            {
                char filename[filename_len];
                memcpy(filename,
                       ((char *)mmap2_rec) + fixed_size,
                       filename_len);

                os->sample.mmap2_entry.file_id = add_global_filename(filename);
            }

            os->type = PERF_RECORD_MMAP2;
            heap_insert(&session->ordered_samples, key, os);
            processed++;

            stats->mmap2_events++;
            break;
        }
        case PERF_RECORD_ITRACE_START:
            stats->itrace_events++;
            break;
        case PERF_RECORD_SWITCH_CPU_WIDE:
            struct switch_cpu_wide *switch_rec = (struct switch_cpu_wide *)header;

            os = (struct ordered_sample *)malloc(sizeof(struct ordered_sample));
            key = (uint64_t *)malloc(sizeof(uint64_t));
            *key = switch_rec->sid.time;
            memcpy(&(os->sample.switch_entry), switch_rec, sizeof(struct switch_cpu_wide));
            os->type = PERF_RECORD_SWITCH_CPU_WIDE;
            heap_insert(&session->ordered_samples, key, os);
            processed++;
            assert(key != NULL && os != NULL);

            stats->switch_cpu_wide_events++;
            break;
        case PERF_RECORD_EXIT:
            struct process_exit *exit = (struct process_exit *)header;

            os = (struct ordered_sample *)malloc(sizeof(struct ordered_sample));
            key = (uint64_t *)malloc(sizeof(uint64_t));
            *key = exit->sid.time;
            memcpy(&(os->sample.exit_entry), exit, sizeof(struct process_exit));
            os->type = PERF_RECORD_EXIT;
            heap_insert(&session->ordered_samples, key, os);
            processed++;
            assert(key != NULL && os != NULL);

            stats->exit_events++;
            break;
        default:
            stats->other++;
            break;
        }
        pmu->meta_page->data_tail += header->size;
        data_tail += header->size;
        asm volatile("dmb ishld" ::: "memory"); // read memory fence

    skip_insert:
        sz += header->size;
    }

    pmu->meta_page->data_tail = data_head;
    return sz;
}

int process_record_aux(struct arm_spe_pmu *pmu, struct cpu_session *session, uint32_t num_cpu, uint32_t spe_period, uint8_t should_throttle)
{
    // these flags caused the aux_offset to be too large and cause issues
    // so if we see this flag we ignore the record

    void *aux = pmu->aux_buffer;

    uint64_t aux_tail = pmu->meta_page->aux_tail;
    uint64_t aux_head = pmu->meta_page->aux_head;
    uint64_t aux_size = pmu->meta_page->aux_size;

    struct ordered_sample *os;
    uint64_t *key;

    uint64_t processed = 0;
    uint64_t throttle_entries = (AUX_THROTTLE_LIMIT / num_cpu) * spe_period / 1000; // e.g., if we are sampling every half a second, we throttle at 
                                                    // half the amount so the average consumption remains under the THROTTLE_LIMIT

    while (aux_tail + sizeof(struct spe_record) < aux_head)
    {
        if (processed >= throttle_entries && should_throttle) break;
        struct spe_record *record = (struct spe_record *)(aux + (aux_tail % aux_size));

        uint8_t *ts = record->timestamp;
        uint64_t timestamp = (uint64_t)ts[0] |
                             ((uint64_t)ts[1] << 8) |
                             ((uint64_t)ts[2] << 16) |
                             ((uint64_t)ts[3] << 24) |
                             ((uint64_t)ts[4] << 32) |
                             ((uint64_t)ts[5] << 40) |
                             ((uint64_t)ts[6] << 48) |
                             ((uint64_t)ts[7] << 56);

        struct aux_entry entry;
        memset(&entry, 0, sizeof(entry));

        parse_record(record, &entry);

        os = (struct ordered_sample *)malloc(sizeof(struct ordered_sample));
        key = (uint64_t *)malloc(sizeof(uint64_t));
        *key = tsc_to_perf_time(timestamp, &session->conv);
        memcpy(&(os->sample.aux_entry), &entry, sizeof(struct aux_entry));
        os->type = PERF_RECORD_AUX;
        assert(key != NULL && os != NULL);
        heap_insert(&session->ordered_samples, key, os);
        processed++;

        aux_tail += sizeof(struct spe_record);
        pmu->meta_page->aux_tail = aux_tail;
    }

    pmu->meta_page->aux_tail = aux_head; // in the case where the buffer we processed wasn't fully written to
}

void parse_record(struct spe_record *record, struct aux_entry *entry)
{
    // parsing logic to get what we want out of the record
    // the byte shifts are intentional. Rather than just reversing bytes,
    // we explicitly shift it to make it little endian and architecture
    // agnostic
    uint64_t pc;
    pc = (uint64_t)record->pc[0] |
         ((uint64_t)record->pc[1] << 8) |
         ((uint64_t)record->pc[2] << 16) |
         ((uint64_t)record->pc[3] << 24) |
         ((uint64_t)record->pc[4] << 32) |
         ((uint64_t)record->pc[5] << 40) |
         ((uint64_t)record->pc[6] << 48);

    entry->pc = pc;

    entry->type = record->type;

    uint16_t total_lat = (uint16_t)record->total_lat[0] | ((uint16_t)record->total_lat[1] << 8);
    uint16_t issue_lat = (uint16_t)record->issue_lat[0] | ((uint16_t)record->issue_lat[1] << 8);
    entry->issue_lat = issue_lat;
    entry->total_lat = total_lat;

    if (issue_lat == AUX_SATURATED_WATERMARK && total_lat == AUX_SATURATED_WATERMARK)
    {
        entry->saturated = 1;
    } else entry->saturated = 0;

    uint32_t events_packet = ((uint32_t)record->events_packet[0]) |
                             ((uint32_t)record->events_packet[1] << 8) |
                             ((uint32_t)record->events_packet[2] << 16) |
                             ((uint32_t)record->events_packet[3] << 24);

    if (events_packet & EVENT_RETIRED)
        entry->retired = 1;

    // packet specific information for loads and branches
    if (record->type == AUX_RECORD_LOAD)
    {
        uint16_t x_lat = (uint32_t)record->x_lat[0] | ((uint32_t)record->x_lat[1] << 8);
        entry->load.data_source = record->data_source;
        entry->load.x_lat = x_lat;
    }
    else if (record->type == AUX_RECORD_BRANCH)
    {
        entry->branch.not_taken = (events_packet & EVENT_BRANCH_NOT_TAKEN) ? 1 : 0;
        entry->branch.mispredicted = (events_packet & EVENT_BRANCH_MISS) ? 1 : 0;

        entry->branch.branch_type = record->reg;
    }
}

// this converts AUX time into perf time that we can directly compare other
// perf records with
uint64_t tsc_to_perf_time(uint64_t cyc, struct perf_tsc_conversion *tc)
{
    uint64_t quot, rem;

    if (tc->cap_user_time_short)
        cyc = tc->time_cycles +
              ((cyc - tc->time_cycles) & tc->time_mask);

    quot = cyc >> tc->time_shift;
    rem = cyc & (((uint64_t)1 << tc->time_shift) - 1);
    return tc->time_zero + quot * tc->time_mult +
           ((rem * tc->time_mult) >> tc->time_shift);
}

void upgrade_ts(struct arm_spe_pmu *pmu, struct cpu_session *session, uint64_t target_ts)
{
    char *data_page = ((char *)pmu->meta_page) + PAGE_SIZE;
    uint64_t data_head = pmu->meta_page->data_head;
    uint64_t data_tail = session->last_record_tail; // use session's last position
    uint64_t data_size = pmu->meta_page->data_size;
    uint64_t last_ts = session->last_record_ts;

    // ensure we don't read past the head
    while (data_tail < data_head) 
    {
        // check if we have enough space for at least a header
        if (data_tail + sizeof(struct perf_event_header) > data_head) {
            break;
        }

        struct perf_event_header *header = (struct perf_event_header *)(data_page + (data_tail % data_size));
        
        // validate header size
        if (header->size == 0 || data_tail + header->size > data_head) {
            break;
        }

        uint64_t current_ts = 0;

        // extract timestamp based on record type
        switch (header->type)
        {
        case PERF_RECORD_MMAP2:
        {
            struct mmap2_record *mmap2_rec = (struct mmap2_record *)header;
            size_t fixed_size = offsetof(struct mmap2_record, filename);
            size_t filename_len = header->size - fixed_size - sizeof(struct sample_id);
            struct sample_id *sid = (struct sample_id *)((char *)mmap2_rec + fixed_size + filename_len);
            current_ts = sid->time;
            break;
        }
        case PERF_RECORD_SWITCH_CPU_WIDE:
        {
            struct switch_cpu_wide *switch_rec = (struct switch_cpu_wide *)header;
            current_ts = switch_rec->sid.time;
            break;
        }
        case PERF_RECORD_EXIT:
        {
            struct process_exit *exit = (struct process_exit *)header;
            current_ts = exit->sid.time;
            break;
        }
        default:
            // skip unknown record types
            data_tail += header->size;
            continue;
        }

        // stop if we've reached a timestamp greater than our target
        if (current_ts > target_ts) {
            break;
        }

        // update last_ts if we have a valid timestamp
        if (current_ts > last_ts) {
            last_ts = current_ts;
        }

        // process the record based on its type
        switch (header->type)
        {
        case PERF_RECORD_MMAP2:
        {
            struct mmap2_record *mmap2_rec = (struct mmap2_record *)header;
            size_t fixed_size = offsetof(struct mmap2_record, filename);
            size_t filename_len = header->size - fixed_size - sizeof(struct sample_id);

            struct ordered_sample *os = (struct ordered_sample *)malloc(sizeof(struct ordered_sample));
            if (!os) {
                // handle allocation failure
                goto next_record;
            }

            memcpy(&(os->sample.mmap2_entry), mmap2_rec, fixed_size);

            if (filename_len > 0) {
                char filename[filename_len + 1];
                memcpy(filename, ((char *)mmap2_rec) + fixed_size, filename_len);
                filename[filename_len] = '\0';  // ensure null termination
                os->sample.mmap2_entry.file_id = add_global_filename(filename);
            }

            os->type = PERF_RECORD_MMAP2;
            handle_mmap2_record(mapping_table, (struct mmap2_mapping *)&os->sample.mmap2_entry);
            free(os);
            break;
        }

        case PERF_RECORD_SWITCH_CPU_WIDE:
        {
            struct switch_cpu_wide *switch_rec = (struct switch_cpu_wide *)header;
            if (switch_rec->header.misc & PERF_RECORD_MISC_SWITCH_OUT) {
                if (switch_rec->next_prev_pid >= 0 && switch_rec->next_prev_pid < ((2 << 21) - 1)) {
                    session->pid = switch_rec->next_prev_pid;
                }
            }
            break;
        }

        case PERF_RECORD_EXIT:
        {
            struct process_exit *exit = (struct process_exit *)header;
            free_pid_maps(mapping_table, exit->pid);
            break;
        }
        }

next_record:
        data_tail += header->size;
        asm volatile("dmb ishld" ::: "memory"); // memory barrier for reading
    }

    // update session state
    session->last_record_ts = last_ts;
    session->last_record_tail = data_tail;
    pmu->meta_page->data_tail = data_tail;
}

void traverse_buffers(struct arm_spe_pmu *pmu, struct cpu_session *session)
{
    void *aux = pmu->aux_buffer;
    uint64_t aux_size = pmu->meta_page->aux_size;
    uint64_t aux_head = pmu->meta_page->aux_head;
    uint64_t aux_tail = session->last_aux_tail;

    uint64_t last_processed_ts = 0;

    // ensure we don't read past the head
    while (aux_tail + sizeof(struct spe_record) <= aux_head)
    {
        struct spe_record *record = (struct spe_record *)(aux + (aux_tail % aux_size));
        
        // extract timestamp
        uint8_t *ts = record->timestamp;
        uint64_t timestamp = (uint64_t)ts[0] |
                           ((uint64_t)ts[1] << 8) |
                           ((uint64_t)ts[2] << 16) |
                           ((uint64_t)ts[3] << 24) |
                           ((uint64_t)ts[4] << 32) |
                           ((uint64_t)ts[5] << 40) |
                           ((uint64_t)ts[6] << 48) |
                           ((uint64_t)ts[7] << 56);

        uint64_t perf_ts = tsc_to_perf_time(timestamp, &session->conv);
        
        // only process if this timestamp is greater than our last processed timestamp
        if (perf_ts >= last_processed_ts) {
            struct aux_entry entry;
            parse_record(record, &entry);

            // process all records up to this timestamp
            upgrade_ts(pmu, session, perf_ts);
            
            // process the aux record itself
            handle_aux_record(session, &entry);
            
            last_processed_ts = perf_ts;
        }

        aux_tail += sizeof(struct spe_record);
        session->last_aux_tail = aux_tail;
        pmu->meta_page->aux_tail = aux_tail;
        asm volatile("dmb ishld" ::: "memory"); // read memory fence
    }
}

// this is the main loop to process all the heap entries. Currently
// an expensive operation due to large amounts of context switch records
// but we can improve on this by inserting less switch records, at the cost
// of a bit of accuracy
long drain_heap(struct cpu_session *session)
{
    if (!session)
    {
        fprintf(stderr, "NULL session passed to drain_heap\n");
        return -1;
    }

    heap *h = &session->ordered_samples;
    void *min_key, *min_val;
    long processed = 0;

    if (heap_size(h) == 0)
    {
        return 0;
    }

    uint64_t failed = 0, succeeded = 0;

    while (heap_delmin(h, &min_key, &min_val))
    {
        if (!min_key || !min_val)
        {
            fprintf(stderr, "NULL pointer returned from heap_delmin\n");
            break;
        }

        uint64_t *key = (uint64_t *)min_key;
        // printf("key: %lu\n", *key);
        struct ordered_sample *val = (struct ordered_sample *)min_val;

        switch (val->type)
        {
        case PERF_RECORD_AUX:
            // handle AUX record by inserting into b-tree
            struct aux_entry *aux_rec = (struct aux_entry *)&val->sample.aux_entry;
            int res = handle_aux_record(session, aux_rec);
            failed += (1-res);
            succeeded += res;
            break;
        case PERF_RECORD_MMAP2:
            // handle MMAP2 record by updating mapping-table
            struct mmap2_mapping *mmap_rec = (struct mmap2_mapping *)&val->sample.mmap2_entry;
            handle_mmap2_record(mapping_table, mmap_rec);
            break;
        case PERF_RECORD_SWITCH_CPU_WIDE:
            // handle SWITCH record by updating mapping-table
            struct switch_cpu_wide *switch_rec = (struct switch_cpu_wide *)&val->sample.switch_entry;
            if (switch_rec->header.misc & PERF_RECORD_MISC_SWITCH_OUT)
            {
                if (switch_rec->next_prev_pid >= 0 && switch_rec->next_prev_pid < ((2 << 21) - 1)) {
                    session->pid = switch_rec->next_prev_pid; // pid switched out of
                }

                assert(session->pid >= 0);
            }
            break;
        case PERF_RECORD_EXIT:
            // handle EXIT record by updating session pid
            struct process_exit *exit_rec = (struct process_exit *)&val->sample.exit_entry;
            if (exit_rec->pid >= 0 && exit_rec->pid < ((2 << 21) - 1)) {
                free_pid_maps(mapping_table, exit_rec->pid);
            }
            break;
        default:
            fprintf(stderr, "Unknown record type: %d\n", val->type);
            break;
        }

        free(key);
        free(val);
        processed++;
    }

    return processed;
}

bool handle_aux_record(struct cpu_session *session, struct aux_entry *entry)
{
    pid_t pid = session->pid;
    assert(pid >= 0);
    struct pid_maps *maps = get_pid_maps(mapping_table, pid);
    char *filename;
    uint64_t file_off;

    if (pc_to_file_offset(maps, entry->pc, &filename, &file_off))
    {
        // this branch is when we successfully map a pc
        // based on if it is a branch or load packet we handle it differently
        // 1. convert to a PC
        // 2. if successful, request the entry from the btree
        // 3. modify that entry (or create a new one if it doesn't exist) based on load or branch
        // 4. insert into btree

        uint64_t file_id = add_global_filename(filename);
        struct vm_spe_btree_entry key = {
            .file_id = file_id,
            .offset = file_off,
            .type = entry->type};

        const struct vm_spe_btree_entry *btree_entry = btree_get(vm_spe_tr, &key);
        struct completion_hist l1, l2, l3, dram;

        struct vm_spe_btree_entry new_entry;
        memset(&new_entry, 0, sizeof(struct vm_spe_btree_entry));

        new_entry.type = entry->type;
        new_entry.file_id = file_id;
        new_entry.offset = file_off;
        if (entry->saturated == 1)
        {
            memcpy(&new_entry, &btree_entry, sizeof(struct vm_spe_btree_entry));
            new_entry.saturated_packets = btree_entry ? btree_entry->saturated_packets + 1 : 1;
            btree_set(vm_spe_tr, &new_entry);
            return false;
        }

        new_entry.retired_insts = btree_entry ? btree_entry->retired_insts + 1 : 1;
        new_entry.total_latency = btree_entry ? btree_entry->total_latency + entry->total_lat : entry->total_lat;
        new_entry.issue_latency = btree_entry ? btree_entry->issue_latency + entry->issue_lat : entry->issue_lat;

        if (entry->type == AUX_RECORD_LOAD)
        {
            struct completion_hist l1, l2, l3, dram;

            if (btree_entry == NULL)
            {
                memset(&l1, 0, sizeof(struct completion_hist));
                memset(&l2, 0, sizeof(struct completion_hist));
                memset(&l3, 0, sizeof(struct completion_hist));
                memset(&dram, 0, sizeof(struct completion_hist));
            }
            else
            {
                l1 = btree_entry->load_entry.l1;
                l2 = btree_entry->load_entry.l2;
                l3 = btree_entry->load_entry.l3;
                dram = btree_entry->load_entry.dram;
            }

            struct completion_hist *bin = NULL;
            uint16_t execution_latency = entry->total_lat - entry->issue_lat - entry->load.x_lat;

            switch (entry->load.data_source)
            {
            case (L1):
                bin = &l1;
                break;
            case (L2):
                bin = &l2;
                break;
            case (LOCAL_CLUSTER):
            case (PEER_CLUSTER):
            case (SYSTEM_CACHE):
                bin = &l3;
                break;
            case (REMOTE):
            case (DRAM):
                bin = &dram;
                break;
            }

            if (execution_latency < L1_BOUND_BIN)
                bin->bin_1++;
            else if (execution_latency < L2_BOUND_BIN)
                bin->bin_2++;
            else if (execution_latency < L3_BOUND_BIN)
                bin->bin_3++;
            else
                bin->bin_4++;

            new_entry.load_entry.x_latency = btree_entry ? btree_entry->load_entry.x_latency + entry->load.x_lat : entry->load.x_lat;
            new_entry.load_entry.l1 = l1;
            new_entry.load_entry.l2 = l2;
            new_entry.load_entry.l3 = l3;
            new_entry.load_entry.dram = dram;
            // new_entry.saturated_packets = btree_entry ? btree_entry->saturated_packets : 0; 
            btree_set(vm_spe_tr, &new_entry);
            return true;
        }
        else if (entry->type == AUX_RECORD_BRANCH)
        {
            new_entry.branch_entry.not_taken_branches = btree_entry ? btree_entry->branch_entry.not_taken_branches + entry->branch.not_taken : entry->branch.not_taken;
            new_entry.branch_entry.mispredicted = btree_entry ? btree_entry->branch_entry.mispredicted + entry->branch.mispredicted : entry->branch.mispredicted;
            new_entry.branch_entry.branch_type = entry->branch.branch_type;
            // new_entry.saturated_packets = btree_entry ? btree_entry->saturated_packets : 0; 
            btree_set(vm_spe_tr, &new_entry);
            return true;
        }
        return false;
    }
    return false;
}