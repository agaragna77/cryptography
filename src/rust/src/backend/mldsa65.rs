// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mldsa65")]
pub(crate) struct MlDsa65PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mldsa65")]
pub(crate) struct MlDsa65PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<MlDsa65PrivateKey> {
    Ok(MlDsa65PrivateKey {
        pkey: openssl::pkey::PKey::generate_ml_dsa(openssl::pkey_ml_dsa::Variant::MlDsa65)?,
    })
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa65PrivateKey {
    MlDsa65PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa65PublicKey {
    MlDsa65PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn from_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa65PrivateKey> {
    let pkey = openssl::pkey::PKey::private_key_from_seed(
        openssl::pkey_ml_dsa::Variant::MlDsa65,
        data.as_bytes(),
    )
    .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid ML-DSA-65 private key"))?;
    Ok(MlDsa65PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<MlDsa65PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes_ex(data, "ML-DSA-65")
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid ML-DSA-65 public key"))?;
    Ok(MlDsa65PublicKey { pkey })
}

#[pyo3::pymethods]
impl MlDsa65PrivateKey {
    #[pyo3(signature = (data, context=None))]
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if let Some(ctx) = context {
            let signature = openssl::pkey_ml_dsa::sign_with_context(
                &self.pkey,
                openssl::pkey_ml_dsa::Variant::MlDsa65,
                data.as_bytes(),
                ctx.as_bytes(),
            )?;
            return Ok(pyo3::types::PyBytes::new(py, &signature));
        }
        let mut signer = openssl::sign::Signer::new_without_digest(&self.pkey)?;
        let len = signer.len()?;
        Ok(pyo3::types::PyBytes::new_with(py, len, |b| {
            let n = signer
                .sign_oneshot(b, data.as_bytes())
                .map_err(CryptographyError::from)?;
            assert_eq!(n, b.len());
            Ok(())
        })?)
    }

    fn sign_with_context<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.sign(py, data, Some(context))
    }

    fn public_key(&self) -> CryptographyResult<MlDsa65PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlDsa65PublicKey {
            pkey: openssl::pkey::PKey::public_key_from_raw_bytes_ex(&raw_bytes, "ML-DSA-65")?,
        })
    }

    fn seed_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let params = self
            .pkey
            .ml_dsa(openssl::pkey_ml_dsa::Variant::MlDsa65)?
            .ok_or_else(|| {
                CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "Invalid ML-DSA-65 private key",
                ))
            })?;
        let seed = params.private_key_seed().map_err(|_| {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                "ML-DSA-65 private key seed not available",
            ))
        })?;
        Ok(pyo3::types::PyBytes::new(py, seed))
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().pkey,
            encoding,
            format,
            encryption_algorithm,
            true,
            true,
        )
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymethods]
impl MlDsa65PublicKey {
    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        let valid = if let Some(ctx) = context {
            openssl::pkey_ml_dsa::verify_with_context(
                &self.pkey,
                openssl::pkey_ml_dsa::Variant::MlDsa65,
                data.as_bytes(),
                signature.as_bytes(),
                ctx.as_bytes(),
            )
            .unwrap_or(false)
        } else {
            openssl::sign::Verifier::new_without_digest(&self.pkey)?
                .verify_oneshot(signature.as_bytes(), data.as_bytes())
                .unwrap_or(false)
        };

        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    fn verify_with_context(
        &self,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        self.verify(signature, data, Some(context))
    }

    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod mldsa65 {
    #[pymodule_export]
    use super::{
        from_public_bytes, from_seed_bytes, generate_key, MlDsa65PrivateKey, MlDsa65PublicKey,
    };
}
