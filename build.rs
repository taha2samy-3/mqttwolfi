use std::path::PathBuf;
use std::process::Command;

/// Build wolfSSL as a static library.
///
/// Two build variants are supported via Cargo features:
///
/// ─────────────────────────────────────────────────────────────────────────────
/// Variant 1: Standard (`--features wolfssl`, default)
/// ─────────────────────────────────────────────────────────────────────────────
///   Source : external/wolfssl  (git submodule → github.com/wolfSSL/wolfssl)
///   Output : external/wolfssl/build/libwolfssl.a
///   Ciphers: Full suite — TLS 1.3, AES-GCM, ChaCha20-Poly1305, all ECDH curves
///   Build  : cargo build                        (default)
///            cargo build --features wolfssl      (explicit)
///
/// ─────────────────────────────────────────────────────────────────────────────
/// Variant 2: FIPS-Ready (`--features wolfssl-fips`)
/// ─────────────────────────────────────────────────────────────────────────────
///   Source : external/wolfssl-fips-bundle/      ← YOU MUST PROVIDE THIS
///            Download the "wolfSSL FIPS Ready" source bundle from:
///            https://www.wolfssl.com/products/wolfcrypt-fips/
///            Extract into: external/wolfssl-fips-bundle/
///
///   Output : external/wolfssl-fips-bundle/build/libwolfssl.a
///   Ciphers: FIPS 140-2/3 approved only:
///            ALLOWED : AES-128/256 CBC+GCM, SHA-224/256/384/512, SHA-3,
///                      RSA 2048+, ECDSA/ECDH P-256/P-384/P-521, HMAC-SHA,
///                      Hash-DRBG (SP 800-90A)
///            REMOVED : ChaCha20-Poly1305, MD5, DES, RC4
///   Build  : cargo build --no-default-features --features wolfssl-fips
///
///   CMVP Note: "FIPS-Ready" uses only FIPS-approved algorithms but does NOT
///   carry a formal CMVP certificate. For a formally validated build
///   (CMVP Certificate #4718), use the wolfSSL FIPS-validated source bundle
///   (requires a wolfSSL commercial license).
///   See: https://www.wolfssl.com/products/wolfcrypt-fips/
///
/// ─────────────────────────────────────────────────────────────────────────────
fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let fips_enabled = std::env::var("CARGO_FEATURE_WOLFSSL_FIPS").is_ok();

    // ── Source directory selection ────────────────────────────────────────────
    let (wolfssl_src, build_dir) = if fips_enabled {
        // FIPS-Ready build requires a separate source bundle (not the open-source tree).
        // The open-source GitHub wolfSSL tree is missing wolfcrypt/src/wolfcrypt_first.c
        // and other proprietary FIPS boundary files that are only in the FIPS bundle.
        let fips_src = manifest_dir.join("external/wolfssl-fips-bundle");
        let fips_build = fips_src.join("build");

        if !fips_src.join("CMakeLists.txt").exists() {
            eprintln!();
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║         wolfSSL FIPS-Ready Source Bundle Not Found           ║");
            eprintln!("╠══════════════════════════════════════════════════════════════╣");
            eprintln!("║                                                              ║");
            eprintln!("║  The FIPS-Ready build requires a wolfSSL FIPS source bundle ║");
            eprintln!("║  that is NOT included in the standard open-source GitHub    ║");
            eprintln!("║  wolfSSL repository.                                        ║");
            eprintln!("║                                                              ║");
            eprintln!("║  HOW TO OBTAIN:                                              ║");
            eprintln!("║  1. Download from: https://wolfssl.com/products/wolfcrypt-fips/");
            eprintln!("║  2. Extract into:  external/wolfssl-fips-bundle/             ║");
            eprintln!("║  3. Rebuild:       cargo build --no-default-features \\      ║");
            eprintln!("║                              --features wolfssl-fips         ║");
            eprintln!("║                                                              ║");
            eprintln!("║  For the standard (non-FIPS) build, use:                    ║");
            eprintln!("║       cargo build   (or --features wolfssl)                 ║");
            eprintln!("║                                                              ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            eprintln!();
            panic!(
                "FIPS-Ready source bundle not found at: {}",
                fips_src.display()
            );
        }

        println!(
            "cargo:warning=wolfSSL FIPS-Ready build: using bundle at {}",
            fips_src.display()
        );
        (fips_src, fips_build)
    } else {
        // Standard build uses the open-source wolfSSL git submodule
        let std_src = manifest_dir.join("external/wolfssl");
        let std_build = std_src.join("build");
        (std_src, std_build)
    };

    // ── CMake build (skip if already built) ──────────────────────────────────
    let lib_path = build_dir.join("libwolfssl.a");
    if !lib_path.exists() {
        // Configure
        let mut cmake_cfg = Command::new("cmake");
        cmake_cfg
            .arg("-S")
            .arg(&wolfssl_src)
            .arg("-B")
            .arg(&build_dir)
            .arg("-DBUILD_SHARED_LIBS=OFF")
            .arg("-DCMAKE_POSITION_INDEPENDENT_CODE=ON")
            .arg("-DWOLFSSL_BUILD_TESTS=OFF")
            .arg("-DWOLFSSL_BUILD_EXAMPLES=OFF")
            .arg("-DWOLFSSL_TLS13=ON")
            .arg("-DWOLFSSL_ALPN=ON")
            .arg("-DWOLFSSL_SNI=ON")
            .arg("-DWOLFSSL_DTLS=ON");

        if fips_enabled {
            cmake_cfg.arg("-DWOLFSSL_FIPS=ON");
        }

        let status = cmake_cfg
            .status()
            .expect("cmake configure failed — is cmake installed?");
        assert!(status.success(), "CMake configure step failed for wolfSSL");

        // Build
        let status = Command::new("cmake")
            .arg("--build")
            .arg(&build_dir)
            .arg("--target")
            .arg("wolfssl")
            .arg("-j4")
            .status()
            .expect("cmake build failed");
        assert!(status.success(), "CMake build step failed for wolfSSL");
    }

    // ── Linker directives ────────────────────────────────────────────────────
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=wolfssl");
    println!("cargo:rerun-if-changed=external/wolfssl/CMakeLists.txt");
    println!("cargo:rerun-if-changed=external/wolfssl-fips-bundle/CMakeLists.txt");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WOLFSSL_FIPS");

    // cfg flag for conditional compilation: #[cfg(wolfssl_fips)]
    if fips_enabled {
        println!("cargo:rustc-cfg=wolfssl_fips");
    }
}
