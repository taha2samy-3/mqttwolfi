use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let wolfssl_src = manifest_dir.join("external/wolfssl");

    // Detect FIPS feature flag set by Cargo
    let fips_enabled = std::env::var("CARGO_FEATURE_WOLFSSL_FIPS").is_ok();

    // Use a distinct build directory per variant to avoid cache conflicts
    let build_dir = if fips_enabled {
        wolfssl_src.join("build_fips")
    } else {
        wolfssl_src.join("build")
    };

    let lib_path = build_dir.join("libwolfssl.a");
    if !lib_path.exists() {
        let mut cmake_cmd = Command::new("cmake");
        cmake_cmd
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
            // Enable FIPS 140-2/140-3 compliant mode.
            // NOTE: FIPS requires a validated wolfSSL FIPS source bundle.
            // The standard open-source wolfSSL tree does NOT include FIPS code.
            // Set FIPS_VERSION to match your validated bundle (v1, v2, v5, etc.)
            cmake_cmd.arg("-DWOLFSSL_FIPS=ON").arg("-DFIPS_VERSION=v5"); // Adjust to your certified bundle version
            println!("cargo:warning=Building wolfSSL in FIPS mode (FIPS_VERSION=v5). Ensure you are using a validated FIPS source bundle.");
        }

        let status = cmake_cmd
            .status()
            .expect("Failed to execute cmake for wolfSSL");
        assert!(status.success(), "cmake configure failed for wolfSSL");

        let status = Command::new("cmake")
            .arg("--build")
            .arg(&build_dir)
            .arg("--target")
            .arg("wolfssl")
            .arg("-j4")
            .status()
            .expect("Failed to build wolfSSL via cmake");
        assert!(status.success(), "cmake build failed for wolfSSL");
    }

    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=wolfssl");
    println!("cargo:rerun-if-changed=external/wolfssl/CMakeLists.txt");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WOLFSSL_FIPS");

    if fips_enabled {
        // Expose the cfg flag so library code can conditionally compile FIPS paths
        println!("cargo:rustc-cfg=wolfssl_fips");
    }
}
