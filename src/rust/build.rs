// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;
use std::path::Path;

#[allow(clippy::unusual_byte_groupings)]
fn main() {
    pyo3_build_config::use_pyo3_cfgs();

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x3_00_09_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_309_OR_GREATER");
        }
        if version >= 0x3_02_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_320_OR_GREATER");
        }
        if version >= 0x3_03_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_330_OR_GREATER");
        }
        if version >= 0x3_05_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_350_OR_GREATER");
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA_SUPPORT");
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA44_SUPPORT");
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA65_SUPPORT");
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA87_SUPPORT");
        }
    }

    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
    }

    // BoringSSL: ML-DSA is available in 0.20251124.0 (November 2025) or later.
    // Detect via capability probe (works with binary-only installs) or CRYPTOGRAPHY_BORINGSSL_VERSION.
    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_BORINGSSL");
        let mut mldsa_supported = false;

        // Prefer probe when OPENSSL_DIR is set (works with binary distribution).
        if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
            let include_dir = Path::new(&openssl_dir).join("include");
            if include_dir.is_dir() {
                let probe_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("probe_mldsa.c");
                if probe_path.is_file() {
                    mldsa_supported = cc::Build::new()
                        .file(&probe_path)
                        .include(&include_dir)
                        .warnings(false)
                        .try_compile("probe_mldsa")
                        .is_ok();
                }
            }
        }

        // Fallback: version env var (e.g. when OPENSSL_DIR is not set).
        if !mldsa_supported {
            const BORINGSSL_MLDSA_MIN_DATE: u32 = 20251124; // 0.20251124.0
            if let Ok(ver) = env::var("CRYPTOGRAPHY_BORINGSSL_VERSION") {
                let date = ver
                    .split('.')
                    .nth(1)
                    .and_then(|s| s.parse::<u32>().ok());
                if date.is_some_and(|d| d >= BORINGSSL_MLDSA_MIN_DATE) {
                    mldsa_supported = true;
                } else {
                    let safe_val = ver
                        .lines()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(80)
                        .collect::<String>();
                    println!("cargo:warning=CRYPTOGRAPHY_BORINGSSL_VERSION invalid or too old (value: {})", safe_val);
                }
            }
        }

        if mldsa_supported {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA_SUPPORT");
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA44_SUPPORT");
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA65_SUPPORT");
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA87_SUPPORT");
            println!("cargo:warning=CRYPTOGRAPHY_MLDSA_SUPPORT enabled (BoringSSL, MLDSA44/65/87)");
        } else {
            println!("cargo:warning=CRYPTOGRAPHY_MLDSA_SUPPORT disabled (BoringSSL)");
        }
    }

    if env::var("DEP_OPENSSL_AWSLC").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_AWSLC");
    }

    if env::var("CRYPTOGRAPHY_BUILD_OPENSSL_NO_LEGACY").is_ok_and(|v| !v.is_empty() && v != "0") {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_BUILD_OPENSSL_NO_LEGACY");
    }

    if let Ok(vars) = env::var("DEP_OPENSSL_CONF") {
        for var in vars.split(',') {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OSSLCONF=\"{var}\"");
        }
    }
}
