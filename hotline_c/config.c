#include "config.h"

void parse_arguments(int argc, char *argv[], struct arg_config *config)
{
    config->period = DEFAULT_PERIOD;
    config->spe_period = DEFAULT_SPE_PERIOD;
    config->num_cpu = DEFAULT_NUM_CPU;
    config->load_filter = DEFAULT_LOAD_FILTER;
    config->timeout = DEFAULT_TIMEOUT;
    config->throttle = 0; // no throttling by default

    static struct option long_options[] = {
        {"period", required_argument, 0, 'p'},
        {"spe_period", required_argument, 0, 's'},
        {"num_cpu", required_argument, 0, 'n'},
        {"load_filter", required_argument, 0, 'l'},
        {"timeout", required_argument, 0, 't'},
        {"throttle", required_argument, 0, 'r'},
        {0, 0, 0, 0}};

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "p:s:n:l:t:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'p':
            config->period = atoi(optarg);
            break;
        case 's':
            config->spe_period = atoi(optarg);
            break;
        case 'n':
            config->num_cpu = atoi(optarg);
            break;
        case 'l':
            config->load_filter = atoi(optarg);
            break;
        case 't':
            config->timeout = atoi(optarg);
            break;
        case 'r':
            config->throttle = atoi(optarg);
        case '?':
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }
}

// spe configurations were determined through several `strace` runs on `perf record`
long configure_ARM_SPE_cpu(int cpu, struct arm_spe_pmu *pmu, struct arg_config *config)
{
    long fd;
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_ARM_SPE_RAW_TYPE;
    attr.config = PERF_ARM_SPE_RAW_CONFIG;
    attr.size = sizeof(attr);
    attr.disabled = 1;
    attr.inherit = 1;
    attr.read_format = PERF_FORMAT_ID | PERF_FORMAT_SPE;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_DATA_SRC | PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_BRANCH_STACK;
    attr.sample_period = config->spe_period;
    attr.sample_id_all = 1;
    attr.context_switch = 1;
    attr.aux_watermark = AUX_WATERMARK;
    attr.enable_on_exec = 1;
    attr.exclude_guest = 1;
    attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
    attr.config2 = config->load_filter;

#ifdef DEBUG
    printf("SPE event configured on CPU %d\n", cpu);
#endif

    fd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd == -1)
    {
        fprintf(stderr, "error opening leader event\n");
        exit(EXIT_FAILURE);
    }
    pmu->fd = fd;
    pmu->cpu = cpu;

    return 0;
}

long mmap_ARM_SPE_cpu(struct arm_spe_pmu *pmu)
{
    struct perf_event_mmap_page *meta_page = NULL;
    if ((meta_page = (struct perf_event_mmap_page *)mmap(NULL,
                                                         (1 + NUM_PAGES) * PAGE_SIZE,
                                                         PROT_READ | PROT_WRITE,
                                                         MAP_SHARED,
                                                         pmu->fd, 0)) == MAP_FAILED)
    {
        fprintf(stderr, "mmap failed: %m\n");
        exit(EXIT_FAILURE);
    }

    meta_page->aux_offset = AUX_OFFSET;
    meta_page->aux_size = AUX_SIZE;

    void *aux_buffer = mmap(NULL, AUX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, pmu->fd, AUX_OFFSET);
    if (aux_buffer == MAP_FAILED)
    {
        fprintf(stderr, "mmap failed: %m\n");
        exit(EXIT_FAILURE);
    }

    pmu->meta_page = meta_page;
    pmu->data_buffer = (char *)meta_page + PAGE_SIZE;
    pmu->aux_buffer = aux_buffer;

    return 0;
}

extern long configure_software_PMU(struct arm_spe_pmu *pmu, struct arg_config *config)
{
    struct perf_event_attr attr;
    long fd;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_DUMMY;
    attr.sample_period = config->spe_period;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_IDENTIFIER;
    attr.read_format = PERF_FORMAT_ID | PERF_FORMAT_SPE;
    attr.disabled = 1;
    attr.inherit = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.mmap = 1;
    attr.comm = 1;
    attr.task = 1;
    attr.sample_id_all = 1;
    attr.exclude_guest = 1;
    attr.mmap2 = 1;
    attr.comm_exec = 1;
    attr.context_switch = 1;
    attr.ksymbol = 1;
    attr.bpf_event = 1;
    attr.watermark = 1;
    fd = perf_event_open(&attr, -1, pmu->cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd == -1)
    {
        fprintf(stderr, "Error opening SPE perf event. Are you on Grv with kernel drivers loaded?\n");
        exit(EXIT_FAILURE);
    }
    pmu->software_fd = fd;
    return 0;
}

// configure both hardware and software file descriptors for CPUs, mmap buffers for them, then configure them to be non-blocking
long configure_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config)
{
    for (int i = 0; i < config->num_cpu; i++)
    {
        configure_ARM_SPE_cpu(i, &pmus[i], config);
        configure_software_PMU(&pmus[i], config);
        mmap_ARM_SPE_cpu(&pmus[i]);
        fcntl(pmus[i].fd, F_SETFL, O_RDONLY | O_NONBLOCK);
        ioctl(pmus[i].software_fd, PERF_EVENT_IOC_SET_OUTPUT, pmus[i].fd);
        fcntl(pmus[i].software_fd, F_SETFL, O_RDONLY | O_NONBLOCK);
    }

    return 0;
}

long toggle_pmu(struct arm_spe_pmu *pmu, uint64_t toggle)
{
    int ret;
    ret = ioctl(pmu->fd, PERF_EVENT_IOC_ENABLE, 0);
    if (ret == -1)
    {
        fprintf(stderr, "toggle failed on hardware PMU");
    }
    ret = ioctl(pmu->software_fd, PERF_EVENT_IOC_ENABLE, 0);
    if (ret == -1)
    {
        fprintf(stderr, "toggle failed on software PMU");
    }
    return 0;
}

long enable_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config)
{
    for (int i = 0; i < config->num_cpu; i++)
    {
        toggle_pmu(&pmus[i], PERF_EVENT_IOC_ENABLE);
    }

#ifdef DEBUG
    printf("All pmus enabled\n");
#endif
    return 0;
}

long disable_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config)
{
    for (int i = 0; i < config->num_cpu; i++)
    {
        toggle_pmu(&pmus[i], PERF_EVENT_IOC_DISABLE);
    }

#ifdef DEBUG
    printf("All pmus disabled\n");
#endif
    return 0;
}

long reset_all_pmus(struct arm_spe_pmu pmus[], struct arg_config *config)
{
    for (int i = 0; i < config->num_cpu; i++)
    {
        toggle_pmu(&pmus[i], PERF_EVENT_IOC_DISABLE);
    }

#ifdef DEBUG
    printf("All pmus reset\n");
#endif
    return 0;
}

void configure_cpu_session(struct cpu_session *session, struct arm_spe_pmu *pmu)
{
    session->conv.cap_user_time_short = 1;
    session->conv.cap_user_time_zero = 1;
    session->conv.time_cycles = pmu->meta_page->time_cycles;
    session->conv.time_mask = pmu->meta_page->time_mask;
    session->conv.time_mult = pmu->meta_page->time_mult;
    session->conv.time_shift = pmu->meta_page->time_shift;
    session->conv.time_zero = pmu->meta_page->time_zero;

    heap_create(&session->ordered_samples, 0, compare_uint64_keys);

    session->pid = 0; // maybe switch to calling process?
    session->last_aux_ts = 0;
    session->last_aux_tail = 0;
}