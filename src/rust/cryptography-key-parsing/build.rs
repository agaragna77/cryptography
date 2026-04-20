// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;

fn main() {
    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
    }

    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_BORINGSSL");
        // Do not set CRYPTOGRAPHY_MLDSA_SUPPORT here: pkcs8/spki ML-DSA paths use
        // openssl::pkey_ml_dsa (ossl350 in rust-openssl), which is unavailable when
        // linking BoringSSL. Boring ML-DSA-44 is handled in cryptography-rust only.
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
