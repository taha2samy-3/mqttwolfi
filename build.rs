use std::path::PathBuf;
use std::process::Command;

/// Build wolfSSL as a static library.
///
/// Two build variants are supported via Cargo features:
///
/// 1. **Standard** (`--features wolfssl`, default)
///    - Full TLS 1.3 + ALPN + SNI + DTLS
///    - No algorithm restrictions
///    - Uses `external/wolfssl/build/` output directory
///
/// 2. **FIPS-Ready** (`--features wolfssl-fips`)
///    - Activates `-DWOLFSSL_FIPS=ON` in CMake
///    - Restricts cipher suites to FIPS 140-2/3 approved algorithms only:
///      AES-CBC/GCM, SHA-2/3, RSA, ECC P-256/384, HMAC-SHA, Hash-DRBG
///    - Disables non-FIPS primitives: ChaCha20-Poly1305, MD5, DES, RC4
///    - Uses a SEPARATE build directory (`external/wolfssl/build_fips/`) to
///      avoid cache conflicts with the standard build
///    - Emits `cfg(wolfssl_fips)` for conditional compilation in Rust code
///
/// FIPS Certification Note
/// =======================
/// `-DWOLFSSL_FIPS=ON` with the open-source wolfSSL tree builds a **FIPS-Ready**
/// binary: it uses only FIPS 140-2/3 approved algorithms and algorithm parameters,
/// but does NOT carry a formal CMVP certificate.
///
/// For a formally FIPS 140-3 *validated* build (CMVP Certificate #4718):
///   1. Download the wolfSSL FIPS validated source bundle from wolfssl.com
///   2. Drop it into `external/wolfssl/` (replacing the open-source checkout)
///   3. Build with `cargo build --features wolfssl-fips`
///   See: https://www.wolfssl.com/products/wolfcrypt-fips/
fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let wolfssl_src = manifest_dir.join("external/wolfssl");

    // Detect which variant Cargo has selected
    let fips_enabled = std::env::var("CARGO_FEATURE_WOLFSSL_FIPS").is_ok();

    // Separate output directories keep the two variants from stepping on each other.
    // This means you can switch features without triggering a full wolfSSL rebuild.
    let build_dir = if fips_enabled {
        wolfssl_src.join("build_fips")
    } else {
        wolfssl_src.join("build")
    };

    let lib_path = build_dir.join("libwolfssl.a");
    if !lib_path.exists() {
        // ── CMake Configure ─────────────────────────────────────────────────
        let mut cmake_cfg = Command::new("cmake");
        cmake_cfg
            .arg("-S")
            .arg(&wolfssl_src)
            .arg("-B")
            .arg(&build_dir)
            // Static lib, position-independent (required for Rust FFI linking)
            .arg("-DBUILD_SHARED_LIBS=OFF")
            .arg("-DCMAKE_POSITION_INDEPENDENT_CODE=ON")
            // Skip test/example build time
            .arg("-DWOLFSSL_BUILD_TESTS=OFF")
            .arg("-DWOLFSSL_BUILD_EXAMPLES=OFF")
            // TLS features needed by the broker
            .arg("-DWOLFSSL_TLS13=ON")
            .arg("-DWOLFSSL_ALPN=ON")
            .arg("-DWOLFSSL_SNI=ON")
            .arg("-DWOLFSSL_DTLS=ON");

        if fips_enabled {
            // Activate FIPS-approved algorithm set only.
            // This restricts ciphers to FIPS 140-2/3 approved primitives:
            //   - Removes ChaCha20-Poly1305 (non-FIPS)
            //   - Removes MD5, DES, RC4 (non-FIPS)
            //   - Forces Hash-DRBG random number generator (FIPS SP 800-90A)
            //   - Sets ECC minimum key to 192-bit (FIPS floor)
            //   - Keeps AES-CBC/GCM, SHA-2/3, RSA 2048+, ECC P-256/384
            cmake_cfg.arg("-DWOLFSSL_FIPS=ON");
            println!(
                "cargo:warning=wolfSSL FIPS-Ready build activated \
                 (FIPS 140-2/3 approved algorithms only). \
                 For a formally validated CMVP certificate, replace external/wolfssl \
                 with a wolfSSL FIPS validated source bundle from wolfssl.com"
            );
        }

        let status = cmake_cfg
            .status()
            .expect("cmake configure failed — is cmake installed?");
        assert!(status.success(), "CMake configure step failed for wolfSSL");

        // ── CMake Build ──────────────────────────────────────────────────────
        let status = Command::new("cmake")
            .arg("--build")
            .arg(&build_dir)
            .arg("--target")
            .arg("wolfssl")
            .arg("-j4")
            .status()
            .expect("cmake build failed — check CMake output above");
        assert!(status.success(), "CMake build step failed for wolfSSL");
    }

    // ── Linker directives ────────────────────────────────────────────────────
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=wolfssl");

    // Rebuild trigger points
    println!("cargo:rerun-if-changed=external/wolfssl/CMakeLists.txt");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WOLFSSL_FIPS");

    // Expose cfg flag for conditional compilation in Rust code:
    //   #[cfg(wolfssl_fips)] fn fips_only_path() { ... }
    if fips_enabled {
        println!("cargo:rustc-cfg=wolfssl_fips");
    }
}
