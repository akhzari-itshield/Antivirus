//! ITShield native acceleration layer (Rust + PyO3).
//!
//! Built with `maturin develop --release` and imported as `itshield_native`.
//! When not built, Python falls back to hashlib for SHA-256.

use pyo3::prelude::*;
use pyo3::exceptions::PyIOError;
use pyo3::types::PyDict;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

// NOTE: Do NOT `use sha2::Digest` at module level — it conflicts with a
// trait from pyo3::prelude::*. Instead, import it inside each function.
use sha2::Sha256;

/// Streaming SHA-256 of a file. Reads in 1 MiB chunks.
#[pyfunction]
fn sha256_file(py: Python<'_>, path: &str) -> PyResult<String> {
    use sha2::Digest;
    let p = Path::new(path);
    if !p.exists() {
        return Err(PyIOError::new_err(format!("file not found: {}", path)));
    }
    if !p.is_file() {
        return Err(PyIOError::new_err(format!("not a regular file: {}", path)));
    }

    let result = py.allow_threads(|| -> std::io::Result<String> {
        let file = File::open(p)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, file);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let digest = hasher.finalize();
        Ok(hex::encode(digest))
    });

    result.map_err(|e| PyIOError::new_err(format!("hash failed: {}", e)))
}

/// Compute SHA-256 of in-memory bytes.
#[pyfunction]
fn sha256_bytes(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Minimal PE parser returning a dict with DOS header + COFF header info.
#[pyfunction]
fn parse_pe(py: Python<'_>, path: &str) -> PyResult<PyObject> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(PyIOError::new_err(format!("file not found: {}", path)));
    }

    let bytes_result = py.allow_threads(|| -> std::io::Result<Vec<u8>> {
        let mut file = File::open(p)?;
        let mut buf = Vec::with_capacity(4096);
        file.read_to_end(&mut buf)?;
        Ok(buf)
    });

    let bytes = bytes_result.map_err(|e| PyIOError::new_err(format!("read failed: {}", e)))?;
    if bytes.len() < 64 {
        return Err(PyIOError::new_err("file too small to be a valid PE"));
    }
    if &bytes[0..2] != b"MZ" {
        return Err(PyIOError::new_err("not a PE file (missing MZ)"));
    }

    let e_lfanew = u32::from_le_bytes([
        bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F],
    ]) as usize;

    if e_lfanew + 24 >= bytes.len() {
        return Err(PyIOError::new_err("invalid PE: e_lfanew out of range"));
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(PyIOError::new_err("invalid PE: missing PE signature"));
    }

    let coff_offset = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([
        bytes[coff_offset + 2], bytes[coff_offset + 3],
    ]);
    let characteristics = u16::from_le_bytes([
        bytes[coff_offset + 18], bytes[coff_offset + 19],
    ]);
    let opt_header_size = u16::from_le_bytes([
        bytes[coff_offset + 16], bytes[coff_offset + 17],
    ]) as usize;

    let opt_magic_offset = coff_offset + 20;
    let opt_magic = if opt_header_size >= 2 {
        u16::from_le_bytes([bytes[opt_magic_offset], bytes[opt_magic_offset + 1]])
    } else {
        0
    };
    let is_pe32_plus = opt_magic == 0x20b;

    let dict = PyDict::new_bound(py);
    let _ = dict.set_item("file_type", "PE");
    let _ = dict.set_item("parser", "rust-native");
    let _ = dict.set_item("size", bytes.len());
    let _ = dict.set_item("e_lfanew", e_lfanew as u64);
    let _ = dict.set_item("num_sections", num_sections);
    let _ = dict.set_item("characteristics", characteristics);
    let _ = dict.set_item("optional_header_size", opt_header_size);
    let _ = dict.set_item("is_pe32_plus", is_pe32_plus);
    let _ = dict.set_item("magic_hex", format!("0x{:04x}", opt_magic));
    Ok(dict.into_any().into())
}

#[pymodule]
fn itshield_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sha256_file, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(parse_pe, m)?)?;
    m.add("__doc__", "ITShield native acceleration layer (Rust).")?;
    Ok(())
}
