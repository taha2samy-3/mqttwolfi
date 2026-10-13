//! Builds wolfSSL as a static library and links it into the broker.
//!
//! Standard build (default `wolfssl` feature)
//!   Source : external/wolfssl (git submodule, pinned to a wolfSSL stable release)
//!   Build  : CMake via the `cmake` crate, into Cargo's OUT_DIR. Cross compilation works with
//!            any target whose C cross compiler is installed (e.g. `aarch64-linux-gnu-gcc`).
//!
//! FIPS-Ready build (`--no-default-features --features wolfssl-fips`)
//!   Source : the wolfSSL FIPS-Ready bundle, a separate download from wolfssl.com (not in this
//!            repository). Point WOLFSSL_FIPS_BUNDLE_DIR at it (default:
//!            external/wolfssl-fips-bundle). Build natively: the integrity hash step runs
//!            wolfCrypt's test program.
//!   Build  : wolfSSL's autotools build with `--enable-fips=ready`, the only build system
//!            wolfSSL supports for FIPS (its CMake build has no FIPS support).
//!   Note   : "FIPS-Ready" means FIPS-approved algorithms only. It is not a CMVP-validated
//!            module; validated builds require wolfSSL's commercial FIPS package.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=WOLFSSL_FIPS_BUNDLE_DIR");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));

    if std::env::var_os("CARGO_FEATURE_WOLFSSL_FIPS").is_some() {
        let bundle = std::env::var_os("WOLFSSL_FIPS_BUNDLE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| manifest.join("external/wolfssl-fips-bundle"));
        build_fips(&bundle);
        println!("cargo:rustc-cfg=wolfssl_fips");
    } else {
        build_standard(&manifest.join("external/wolfssl"));
    }
    println!("cargo:rustc-check-cfg=cfg(wolfssl_fips)");
}

fn build_standard(src: &Path) {
    if !src.join("CMakeLists.txt").exists() {
        panic!(
            "wolfSSL sources not found at {}.\nRun: git submodule update --init --recursive",
            src.display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        src.join("CMakeLists.txt").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        src.join("wolfssl/version.h").display()
    );

    let mut cfg = cmake::Config::new(src);
    cfg.profile("Release")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("CMAKE_POSITION_INDEPENDENT_CODE", "ON")
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .define("WOLFSSL_EXAMPLES", "no")
        .define("WOLFSSL_CRYPT_TESTS", "no")
        .define("WOLFSSL_TLS13", "yes")
        .define("WOLFSSL_TLSV12", "yes")
        .define("WOLFSSL_OLD_TLS", "no")
        .define("WOLFSSL_HARDEN", "yes")
        .define("WOLFSSL_ALPN", "yes")
        .define("WOLFSSL_SNI", "yes")
        .define("WOLFSSL_CURVE25519", "yes")
        .define("WOLFSSL_DTLS", "no")
        .define("WOLFSSL_SYS_CA_CERTS", "no")
        // Client certificate revocation (security.tls.crl_file).
        .define("WOLFSSL_CRL", "yes")
        // Pinned off: TLS 1.3 0-RTT data is replayable, and the broker keeps no TLS sessions.
        .define("WOLFSSL_EARLYDATA", "no")
        .define("WOLFSSL_SESSION_TICKET", "no")
        // Needed for client certificate identity checks (verify_client_identity).
        .cflag("-DKEEP_PEER_CERT");
    let dst = cfg.build();
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=wolfssl");
    link_system_libs();
}

fn build_fips(bundle: &Path) {
    if !bundle.join("configure.ac").exists() && !bundle.join("configure").exists() {
        panic!(
            "\nwolfSSL FIPS-Ready bundle not found at {}.\n\
             Download it from https://www.wolfssl.com/products/wolfcrypt-fips/ and extract it\n\
             there, or set WOLFSSL_FIPS_BUNDLE_DIR. For the standard build run `cargo build`.\n",
            bundle.display()
        );
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let build_dir = out.join("wolfssl-fips-build");
    let prefix = out.join("wolfssl-fips");
    // Autotools builds in-tree; copy the bundle so the source checkout stays clean.
    let _ = std::fs::remove_dir_all(&build_dir);
    copy_dir(bundle, &build_dir).expect("copy FIPS bundle");

    let run = |cmd: &mut Command, what: &str| {
        let status = cmd
            .current_dir(&build_dir)
            .status()
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(
            status.success(),
            "{what} failed for the wolfSSL FIPS bundle"
        );
    };
    if !build_dir.join("configure").exists() {
        run(Command::new("sh").arg("autogen.sh"), "autogen.sh");
    }
    let mut configure = Command::new("sh");
    configure.args([
        "./configure",
        "--enable-fips=ready",
        "--enable-static",
        "--disable-shared",
        "--with-pic",
        "--enable-tls13",
        "--enable-alpn",
        "--enable-sni",
        "--enable-harden",
        "--disable-oldtls",
        "--enable-crl",
        "--disable-earlydata",
        "--disable-session-ticket",
        "--disable-examples",
        // fips-hash.sh runs wolfcrypt/test/testwolfcrypt to read the integrity hash, so the
        // crypt tests must be built (and the build must run natively, not cross-compiled).
        "CPPFLAGS=-DKEEP_PEER_CERT",
    ]);
    configure.arg(format!("--prefix={}", prefix.display()));
    if let (Ok(target), Ok(host)) = (std::env::var("TARGET"), std::env::var("HOST")) {
        if target != host {
            configure.arg(format!("--host={}", gnu_triple(&target)));
        }
    }
    run(&mut configure, "configure");
    let jobs = std::env::var("NUM_JOBS").unwrap_or_else(|_| "4".into());
    run(Command::new("make").arg(format!("-j{jobs}")), "make");
    // FIPS Ready requires the in-core integrity hash to be embedded after the first build.
    if build_dir.join("fips-hash.sh").exists() {
        run(Command::new("sh").arg("./fips-hash.sh"), "fips-hash.sh");
        run(
            Command::new("make").arg(format!("-j{jobs}")),
            "make (after fips-hash)",
        );
    }
    run(Command::new("make").arg("install"), "make install");
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=wolfssl");
    link_system_libs();
}

fn link_system_libs() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match os.as_str() {
        "linux" | "android" => println!("cargo:rustc-link-lib=m"),
        // Winsock, certificate store and the system RNG used by wolfSSL on Windows.
        "windows" => {
            for lib in ["ws2_32", "crypt32", "advapi32"] {
                println!("cargo:rustc-link-lib={lib}");
            }
        }
        _ => {}
    }
}

/// Maps a Rust target triple to the GNU triple autotools expects.
fn gnu_triple(target: &str) -> String {
    target
        .replace("-unknown-linux-", "-linux-")
        .replace("armv7-linux-gnueabihf", "arm-linux-gnueabihf")
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}
