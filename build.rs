use anyhow::Result;
use std::env;
use std::process::Command;

fn main() -> Result<()> {
    let _ = vergen::EmitBuilder::builder().git_sha(true).emit();

    println!("cargo:rerun-if-changed=src/hotline/*");
    println!("cargo:rerun-if-changed=package.json");
    println!("cargo:rerun-if-changed=package-lock.json");
    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu"); // for ARM64

    println!("cargo:rerun-if-changed=package.json");
    println!("cargo:rerun-if-changed=package-lock.json");
    match Command::new("npm").arg("install").spawn() {
        Err(_proc) => {
            println!("Build requires npm, but it was not found. Please install Node >= 16.16.0.");
            std::process::exit(1);
        }
        Ok(mut child) => {
            let status = child.wait()?;
            if !status.success() {
                println!("Command \"npm install\" failed.");
                std::process::exit(1);
            }
        }
    }

    let jsdir = format!("{}/js", env::var("OUT_DIR").unwrap());
    println!("cargo:rustc-env=JS_DIR={}", jsdir);
    println!("cargo:rerun-if-changed=src/html_files/");
    let status = Command::new("npm")
        .arg("exec")
        .arg("--")
        .arg("tsc")
        .arg("-p")
        .arg("src/html_files/")
        .arg("--outDir")
        .arg(jsdir)
        .spawn()?
        .wait()?;
    if !status.success() {
        println!("Failed to compile typescript.");
        std::process::exit(1);
    }

    #[cfg(feature = "spe")]
    {
        cc::Build::new()
            .files([
                "src/hotline/bmiss_map.c",
                "src/hotline/btree.c",
                "src/hotline/config.c",
                "src/hotline/finode_map.c",
                "src/hotline/fname_binary_map.c",
                "src/hotline/fname_map.c",
                "src/hotline/hotline.c",
                "src/hotline/lat_map.c",
                "src/hotline/report.c",
                "src/hotline/sys.c",
                "src/hotline/vec.c",
                "src/hotline/tests/test_bmiss_map.c",
                "src/hotline/tests/test_config.c",
                "src/hotline/tests/test_finode_map.c",
                "src/hotline/tests/test_fname_binary_map.c",
                "src/hotline/tests/test_fname_map.c",
                "src/hotline/tests/test_lat_map.c",
                "src/hotline/tests/test.c",
            ])
            .includes(["src/hotline", "/usr/src/linux-headers-$(uname -r)/include"])
            .static_flag(true)
            .flag("-Werror")
            .flag("-Wextra")
            .opt_level(3)
            .compile("hotline");

        println!("cargo:rustc-link-lib=static=dw");
        println!("cargo:rustc-link-lib=static=elf");
        println!("cargo:rustc-link-lib=static=capstone");
        println!("cargo:rustc-link-lib=static=z");
        println!("cargo:rustc-link-lib=static=lzma");
        println!("cargo:rustc-link-lib=static=bz2");
        println!("cargo:rustc-link-lib=static=zstd");
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=pthread");
        println!("Building with SPE support.");
    }
    Ok(())
}
