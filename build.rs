use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let wolfssl_src = manifest_dir.join("external/wolfssl");
    let build_dir = wolfssl_src.join("build");

    let lib_path = build_dir.join("libwolfssl.a");
    if !lib_path.exists() {
        let status = Command::new("cmake")
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
            .arg("-DWOLFSSL_DTLS=ON")
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
}
