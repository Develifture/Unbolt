//! Windows CNG randomness and streaming SHA-256; no private crypto algorithm.
use crate::{UnboltResult, command::wide};
use serde::Serialize;
use std::{
    io::{self, Write},
    ptr::{null, null_mut},
};
use windows_sys::Win32::Security::Cryptography::*;
pub fn nonce() -> UnboltResult<String> {
    let mut bytes = [0u8; 32];
    if unsafe {
        BCryptGenRandom(
            null_mut(),
            bytes.as_mut_ptr(),
            32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } < 0
    {
        return Err("Cannot obtain a fresh operation nonce".into());
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub fn valid_nonce(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
pub fn same_nonce(a: &str, b: &str) -> bool {
    if !valid_nonce(a) || !valid_nonce(b) {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
pub struct Sha256 {
    algorithm: BCRYPT_ALG_HANDLE,
    hash: BCRYPT_HASH_HANDLE,
    _object: Vec<u8>,
}
impl Drop for Sha256 {
    fn drop(&mut self) {
        unsafe {
            if !self.hash.is_null() {
                BCryptDestroyHash(self.hash);
            }
            if !self.algorithm.is_null() {
                BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
        }
    }
}
impl Sha256 {
    pub fn new() -> UnboltResult<Self> {
        let mut value = Self {
            algorithm: null_mut(),
            hash: null_mut(),
            _object: vec![],
        };
        if unsafe {
            BCryptOpenAlgorithmProvider(&mut value.algorithm, wide("SHA256").as_ptr(), null(), 0)
        } < 0
        {
            return Err("Cannot open SHA-256 provider".into());
        }
        let mut length = 0u32;
        let mut returned = 0;
        if unsafe {
            BCryptGetProperty(
                value.algorithm,
                wide("ObjectLength").as_ptr(),
                (&mut length as *mut u32).cast(),
                4,
                &mut returned,
                0,
            )
        } < 0
            || returned != 4
            || length > 65536
        {
            return Err("Invalid SHA-256 provider state size".into());
        }
        value._object = vec![0; length as usize];
        if unsafe {
            BCryptCreateHash(
                value.algorithm,
                &mut value.hash,
                value._object.as_mut_ptr(),
                length,
                null(),
                0,
                0,
            )
        } < 0
        {
            return Err("Cannot create SHA-256 state".into());
        }
        Ok(value)
    }
    pub fn finish(self) -> UnboltResult<[u8; 32]> {
        let mut result = [0u8; 32];
        if unsafe { BCryptFinishHash(self.hash, result.as_mut_ptr(), 32, 0) } < 0 {
            return Err("Cannot finish SHA-256 fingerprint".into());
        }
        Ok(result)
    }
}
impl Write for Sha256 {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for chunk in bytes.chunks(u32::MAX as usize) {
            if unsafe { BCryptHashData(self.hash, chunk.as_ptr(), chunk.len() as u32, 0) } < 0 {
                return Err(io::Error::other("SHA-256 update failed"));
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn fingerprint<T: Serialize>(value: &T) -> UnboltResult<[u8; 32]> {
    let mut stream = std::io::BufWriter::with_capacity(65536, Sha256::new()?);
    serde_json::to_writer(&mut stream, value).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    stream.into_inner().map_err(|e| e.to_string())?.finish()
}
pub fn file(path: &std::path::Path) -> UnboltResult<[u8; 32]> {
    file_with_cancel(path, &std::sync::atomic::AtomicBool::new(false))
}
pub fn file_with_cancel(
    path: &std::path::Path,
    cancel: &std::sync::atomic::AtomicBool,
) -> UnboltResult<[u8; 32]> {
    use std::io::Read;
    let mut input = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new()?;
    let mut buffer = vec![0u8; 65536];
    loop {
        if crate::model::cancelled(cancel) {
            return Err("File fingerprint cancelled".into());
        }
        let count = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hash.write_all(&buffer[..count])
            .map_err(|e| e.to_string())?;
    }
    hash.finish()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_matches_known_answer_across_streamed_writes() {
        let mut hash = Sha256::new().unwrap();
        hash.write_all(b"a").unwrap();
        hash.write_all(b"bc").unwrap();
        assert_eq!(
            hash.finish()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn nonce_validation_rejects_short_ambiguous_and_changed_values() {
        let a = nonce().unwrap();
        let b = nonce().unwrap();
        assert!(same_nonce(&a, &a));
        assert!(!same_nonce(&a, &b));
        assert!(!same_nonce("", ""));
        assert!(!same_nonce(&a.to_uppercase(), &a));
    }
}
