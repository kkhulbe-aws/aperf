#[cfg(feature = "spe")]
use crate::InitParams;
#[cfg(feature = "spe")]
use anyhow::anyhow;
#[cfg(feature = "spe")]
use anyhow::Result;
#[cfg(feature = "spe")]
use clap::Args;
#[cfg(feature = "spe")]
use log::error;
#[cfg(feature = "spe")]
use std::env;
#[cfg(feature = "spe")]
use std::ffi::CString;
#[cfg(feature = "spe")]
use std::fs;
#[cfg(feature = "spe")]
use std::os::raw::{c_char, c_int};
#[cfg(feature = "spe")]
use std::path::Path;

#[cfg(feature = "spe")]
unsafe extern "C" {
    fn hotline_main(argc: c_int, argv: *const *const i8) -> c_int;
}

#[cfg(feature = "spe")]
#[derive(Args, Debug)]
pub struct SPE {
    /// Name of the run.
    #[clap(short, long, value_parser)]
    pub run_name: Option<String>,

    /// Number of CPUs to profile from id 0 to N-1
    /// Default of 64 because that is supported on all Grv instances
    #[clap(short, long, value_parser, default_value_t = 64)]
    pub num_cpu: u64,

    /// Wake up period (ms)
    #[clap(short, long, value_parser, default_value_t = 1000)]
    pub period: u64,

    /// ARM SPE sampling period (cycles)
    #[clap(short, long, value_parser, default_value_t = 2800000)]
    pub spe_period: u64,

    /// Timeout. How long to run the profile (seconds)
    #[clap(short = 'x', long, value_parser, default_value_t = 60)]
    pub timeout: u64,

    /// Throttle determines wether or not the tool throttles data to prevent
    /// increased CPU usage.
    #[clap(short = 'y', long, value_parser, default_value_t = 0)]
    pub throttle: u8,

    /// Verbose
    #[clap(short, long, value_parser, default_value_t = 0)]
    pub verbose: u8,
}

#[cfg(feature = "spe")]
pub fn spe(record: &SPE, tmp_dir: &Path, runlog: &Path) -> Result<()> {

    let mut run_name = String::new();
    if record.period == 0 {
        error!("Wakeup period cannot be 0.");
        return Err(anyhow!("Cannot start recording with the given parameters."));
    }
    if record.spe_period == 0 {
        error!("SPE sampling interval cannot be 0.");
        return Err(anyhow!("Cannot start recording with the given parameters."));
    }

    match &record.run_name {
        Some(r) => run_name = r.clone(),
        None => {}
    }

    let mut params = InitParams::new(run_name);
    fs::create_dir(params.dir_name.clone())?;
    params.period = record.period;
    params.tmp_dir = tmp_dir.to_path_buf();
    params.runlog = runlog.to_path_buf();

    unsafe {
        env::set_var("HOTLINE_DIR", params.dir_name);
    }

    unsafe {
        env::set_var("HOTLINE_VERBOSE", record.verbose.to_string());
    }

    // create the argument strings
    let args = vec![
        CString::new("hotline").unwrap(),
        CString::new("--num_cpu").unwrap(),
        CString::new(record.num_cpu.to_string()).unwrap(),
        CString::new("--period").unwrap(),
        CString::new(record.period.to_string()).unwrap(),
        CString::new("--spe_period").unwrap(),
        CString::new(record.spe_period.to_string()).unwrap(),
        CString::new("--timeout").unwrap(),
        CString::new(record.timeout.to_string()).unwrap(),
        CString::new("--throttle").unwrap(),
        CString::new(record.throttle.to_string()).unwrap(),
    ];

    // create array of pointers to arguments
    let argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();

    // call hotline_main
    unsafe {
        let result = hotline_main(args.len() as c_int, argv.as_ptr() as *const *const i8);

        if result != 0 {
            println!("Hotline finished with status: {}", result);
            return Err(anyhow::anyhow!("Hotline failed with status: {}", result));
        }
    }
    Ok(())
}
