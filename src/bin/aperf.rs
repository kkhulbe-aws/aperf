use anyhow::Result;
use aperf::pmu::{custom_pmu, CustomPMU};
use aperf::record::{record, Record};
use aperf::report::{report, Report};
use aperf::{PDError, APERF_RUNLOG, APERF_TMP};
use clap::{Parser, Subcommand};
use log::LevelFilter;
use log::{debug, info, warn};
use log4rs::{
    append::console::ConsoleAppender,
    append::file::FileAppender,
    config::{Appender, Config, Logger, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};
use std::io::{self};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
use tempfile::Builder as TempBuilder;

#[derive(Parser)]
#[command(author, about, long_about = None)]
#[command(name = "aperf")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("VERGEN_GIT_SHA"), ")"))]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Show debug messages. Use -vv for more verbose messages.
    #[clap(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Temporary directory for intermediate files.
    #[clap(short, long, value_parser, default_value_t = APERF_TMP.to_string(), global = true)]
    tmp_dir: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Collect performance data.
    Record(Record),

    /// Generate an HTML report based on the data collected.
    Report(Report),

    /// Create a custom PMU configuration file for use with Aperf record.
    CustomPMU(CustomPMU),
}

fn init_logger(verbose: u8, runlog: &PathBuf) -> Result<()> {
    let level = match verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        2 => LevelFilter::Trace,
        _ => return Err(PDError::InvalidVerboseOption.into()),
    };
    let pattern = "[{d(%Y-%m-%dT%H:%M:%SZ)} {h({l}):5.5} {M}] {m}{n}";
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    let fileout = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build(runlog)?;

    let config = Config::builder()
        /* This prints only the user selected level to the console. */
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(level)))
                .build("stdout", Box::new(stdout)),
        )
        .appender(Appender::builder().build("aperflog", Box::new(fileout)))
        /* This creates a logger for our module at a default Debug level. */
        .logger(
            Logger::builder()
                .appender("aperflog")
                .appender("stdout")
                .build(env!("CARGO_CRATE_NAME"), LevelFilter::Debug),
        )
        .build(
            /* Set the Root to Warn. Underlying dependencies also print if set to debug.
             * See: https://github.com/estk/log4rs/issues/196
             */
            Root::builder().build(LevelFilter::Warn),
        )?;

    log4rs::init_config(config)?;
    Ok(())
}

pub fn check_preconditions() -> io::Result<()> {
    // Check KPTI status
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let kpti_off = cmdline.contains("kpti=off");

    // Check kptr_restrict
    let kptr_value = fs::read_to_string("/proc/sys/kernel/kptr_restrict")?
        .trim()
        .parse::<i32>()
        .unwrap_or(-1);

    // Check perf_event_paranoid
    let paranoid_value = fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")?
        .trim()
        .parse::<i32>()
        .unwrap_or(4);

    // Check /proc/kallsyms readable
    let kallsyms_readable = fs::metadata("/proc/kallsyms")
        .map(|metadata| metadata.permissions().readonly())
        .unwrap_or(false);

    if !kallsyms_readable {
        warn!("/proc/kallsyms is not readable");
    }

    // Check if all conditions are met
    if !kpti_off || kptr_value != 0 || paranoid_value != -1 || !kallsyms_readable {
        warn!("Not all preconditions are met.");
        warn!("Please ensure:");
        warn!("1. KPTI is disabled (add 'kpti=off' to GRUB_CMDLINE_LINUX_DEFAULT and reboot)");
        warn!("2. echo 0 > /proc/sys/kernel/kptr_restrict");
        warn!("3. echo -1 > /proc/sys/kernel/perf_event_paranoid");
        warn!("4. chmod +r /proc/kallsyms");
    } else {
        info!("All preconditions are met.")
    }

    debug!("Preconditions check completed: kpti_off={}, kptr_value={}, paranoid_value={}, kallsyms_readable={}", 
           kpti_off, kptr_value, paranoid_value, kallsyms_readable);

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let tmp_dir = TempBuilder::new()
        .prefix("aperf-tmp-")
        .tempdir_in(&cli.tmp_dir)?;
    fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o1777))?;
    let tmp_dir_path_buf = tmp_dir.path().to_path_buf();
    let runlog = tmp_dir_path_buf.join(APERF_RUNLOG);

    init_logger(cli.verbose, &runlog)?;

    let _ = check_preconditions();

    match cli.command {
        Commands::Record(r) => record(&r, &tmp_dir_path_buf, &runlog),
        Commands::Report(r) => report(&r, &tmp_dir_path_buf),
        Commands::CustomPMU(r) => custom_pmu(&r),
    }?;
    fs::remove_dir_all(tmp_dir_path_buf)?;
    Ok(())
}
