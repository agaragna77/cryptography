// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;
use std::path::Path;

fn main() {
    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
    }

    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_BORINGSSL");
        let mut mldsa_supported = false;
        if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
            let include_dir = Path::new(&openssl_dir).join("include");
            if include_dir.is_dir() {
                let probe_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .map(|p| p.join("probe_mldsa.c"));
                if let Some(probe_path) = probe_path {
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
        }
        if !mldsa_supported {
            const BORINGSSL_MLDSA_MIN_DATE: u32 = 20251124;
            if let Ok(ver) = env::var("CRYPTOGRAPHY_BORINGSSL_VERSION") {
                if ver
                    .split('.')
                    .nth(1)
                    .and_then(|s| s.parse::<u32>().ok())
                    .is_some_and(|d| d >= BORINGSSL_MLDSA_MIN_DATE)
                {
                    mldsa_supported = true;
                }
            }
        }
        if mldsa_supported {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA_SUPPORT");
        }
    }

    if env::var("DEP_OPENSSL_AWSLC").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_AWSLC");
    }

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();
        if version >= 0x3050_0000 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_350_OR_GREATER");
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_MLDSA_SUPPORT");
        }
    }

    if let Ok(vars) = env::var("DEP_OPENSSL_CONF") {
        for var in vars.split(',') {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OSSLCONF=\"{var}\"");
        }
    }
}
