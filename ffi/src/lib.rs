use std::ffi::{CStr, CString};

mod bindings {
    #![allow(
        unused,
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        // Silence "128-bit integers don't currently have a known stable ABI" warnings
        improper_ctypes,
        // Silence "constants have by default a `'static` lifetime" clippy warnings
        clippy::redundant_static_lifetimes,
        // https://github.com/rust-lang/rust-bindgen/issues/1651
        deref_nullptr,
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub fn generate_groth16_proof(
    common_circuit_data: &str,
    proof_with_public_inputs: &str,
    verifier_only_circuit_data: &str,
    keystore_path: &str,
) -> (String, String) {
    let c_common_circuit_data = CString::new(common_circuit_data).unwrap();
    let c_proof_with_public_inputs = CString::new(proof_with_public_inputs).unwrap();
    let c_verifier_only_circuit_data = CString::new(verifier_only_circuit_data).unwrap();
    let c_keystore_path = CString::new(keystore_path).unwrap();
    unsafe {
        let c_proof_with_vk = bindings::GenerateGroth16Proof(
            c_common_circuit_data.into_raw(),
            c_proof_with_public_inputs.into_raw(),
            c_verifier_only_circuit_data.into_raw(),
            c_keystore_path.into_raw(),
        );
        let proof = CStr::from_ptr((*c_proof_with_vk).proof).to_string_lossy().into_owned();
        let vk = CStr::from_ptr((*c_proof_with_vk).vk).to_string_lossy().into_owned();
        libc::free(c_proof_with_vk as *mut libc::c_void);
        (proof, vk)
    }
}

/// JSON-aware version: accepts JSON strings directly without needing plonky2 Rust types.
/// This avoids serde on plonky2 types and goes straight through the Go FFI.
pub fn generate_groth16_proof_from_json(
    common_circuit_data_json: &str,
    proof_with_public_inputs_json: &str,
    verifier_only_circuit_data_json: &str,
    keystore_path: &str,
) -> (String, String) {
    let c_common = CString::new(common_circuit_data_json).unwrap();
    let c_proof = CString::new(proof_with_public_inputs_json).unwrap();
    let c_verifier = CString::new(verifier_only_circuit_data_json).unwrap();
    let c_keystore = CString::new(keystore_path).unwrap();
    unsafe {
        let c_proof_with_vk = bindings::GenerateGroth16ProofFromJson(
            c_common.into_raw(),
            c_proof.into_raw(),
            c_verifier.into_raw(),
            c_keystore.into_raw(),
        );
        let proof = CStr::from_ptr((*c_proof_with_vk).proof).to_string_lossy().into_owned();
        let vk = CStr::from_ptr((*c_proof_with_vk).vk).to_string_lossy().into_owned();
        libc::free(c_proof_with_vk as *mut libc::c_void);
        (proof, vk)
    }
}

/// Thin convenience wrapper:
/// generate canonical gnark JSON, then convert to city-compressed JSON.
pub fn generate_groth16_proof_from_json_compressed(
    common_circuit_data_json: &str,
    proof_with_public_inputs_json: &str,
    verifier_only_circuit_data_json: &str,
    keystore_path: &str,
) -> (String, String) {
    let (proof, vk) = generate_groth16_proof_from_json(
        common_circuit_data_json,
        proof_with_public_inputs_json,
        verifier_only_circuit_data_json,
        keystore_path,
    );
    convert_groth16_to_compressed(&proof, &vk)
}

pub fn verify_groth16_proof(
    proof_string: &str,
    vk_string: &str,
) -> bool {
    verify_groth16_proof_uncompressed(proof_string, vk_string)
}

pub fn verify_groth16_proof_uncompressed(
    proof_string: &str,
    vk_string: &str,
) -> bool {
    let c_proof_string = CString::new(proof_string).unwrap();
    let c_vk_string = CString::new(vk_string).unwrap();
    unsafe {
        bindings::VerifyGroth16ProofUncompressed(
            c_proof_string.into_raw(),
            c_vk_string.into_raw(),
        ) != 0
    }
}

pub fn verify_groth16_proof_compressed(
    proof_string: &str,
    vk_string: &str,
) -> bool {
    let c_proof_string = CString::new(proof_string).unwrap();
    let c_vk_string = CString::new(vk_string).unwrap();
    unsafe {
        bindings::VerifyGroth16ProofCompressed(
            c_proof_string.into_raw(),
            c_vk_string.into_raw(),
        ) != 0
    }
}

pub fn convert_groth16_to_compressed(
    proof_string: &str,
    vk_string: &str,
) -> (String, String) {
    let c_proof_string = CString::new(proof_string).unwrap();
    let c_vk_string = CString::new(vk_string).unwrap();
    unsafe {
        let c_proof_with_vk = bindings::ConvertGroth16ToCompressed(
            c_proof_string.into_raw(),
            c_vk_string.into_raw(),
        );
        let proof = CStr::from_ptr((*c_proof_with_vk).proof).to_string_lossy().into_owned();
        let vk = CStr::from_ptr((*c_proof_with_vk).vk).to_string_lossy().into_owned();
        libc::free(c_proof_with_vk as *mut libc::c_void);
        (proof, vk)
    }
}

pub fn initialize(key_path: &str) {
    let c_key_path_string = CString::new(key_path).unwrap();
    unsafe {
        bindings::Initialize(c_key_path_string.into_raw());
    }
}

pub fn export_solidity_verifier(keystore_path: &str) -> String {
    let c_keystore_path = CString::new(keystore_path).unwrap();
    unsafe {
        let c_result = bindings::ExportSolidityVerifier(c_keystore_path.into_raw());
        let result = CStr::from_ptr(c_result).to_string_lossy().into_owned();
        libc::free(c_result as *mut libc::c_void);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    struct TestContext {
        proof_json: String,
        vk_json: String,
        keystore_path: String,
    }

    fn fixture_dir() -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("plonky2_proof")
            .join("0");
        if !dir.exists() {
            panic!("fixture directory not found: {}", dir.display());
        }
        dir
    }

    fn load_fixture(path: &Path, file: &str) -> String {
        let file_path = path.join(file);
        std::fs::read_to_string(&file_path)
            .unwrap_or_else(|e| panic!("failed to read fixture {}: {}", file_path.display(), e))
    }

    fn flip_first_hex_nibble(hex: &str) -> String {
        let mut chars: Vec<char> = hex.chars().collect();
        if let Some(first) = chars.first_mut() {
            *first = if *first == '0' { '1' } else { '0' };
        }
        chars.into_iter().collect()
    }

    fn test_context() -> &'static TestContext {
        static CONTEXT: OnceLock<TestContext> = OnceLock::new();
        CONTEXT.get_or_init(|| {
            let path = fixture_dir();
            let keystore_path = "/tmp/groth16-keystore/ffi-tests/".to_string();
            let (proof_json, vk_json) = generate_groth16_proof(
                &load_fixture(&path, "common_circuit_data.json"),
                &load_fixture(&path, "proof_with_public_inputs.json"),
                &load_fixture(&path, "verifier_only_circuit_data.json"),
                &keystore_path,
            );
            TestContext {
                proof_json,
                vk_json,
                keystore_path,
            }
        })
    }

    #[test]
    fn generate_groth16_proof_test() {
        let ctx = test_context();
        assert!(!ctx.proof_json.is_empty(), "proof json should not be empty");
        assert!(!ctx.vk_json.is_empty(), "vk json should not be empty");
    }

    #[test]
    fn verify_groth16_proof_test() {
        let ctx = test_context();
        assert!(verify_groth16_proof_uncompressed(&ctx.proof_json, &ctx.vk_json));
        // Backward-compatible API keeps uncompressed semantics.
        assert!(verify_groth16_proof(&ctx.proof_json, &ctx.vk_json));
    }

    #[test]
    fn generate_groth16_proof_from_json_test() {
        let path = fixture_dir();
        let keystore_path = "/tmp/groth16-keystore/ffi-tests/".to_string();
        let (proof_json, vk_json) = generate_groth16_proof_from_json(
            &load_fixture(&path, "common_circuit_data.json"),
            &load_fixture(&path, "proof_with_public_inputs.json"),
            &load_fixture(&path, "verifier_only_circuit_data.json"),
            &keystore_path,
        );

        assert!(!proof_json.is_empty(), "proof json should not be empty");
        assert!(!vk_json.is_empty(), "vk json should not be empty");
        assert!(verify_groth16_proof_uncompressed(&proof_json, &vk_json));
    }

    #[test]
    fn generate_groth16_proof_from_json_compressed_test() {
        let path = fixture_dir();
        let keystore_path = "/tmp/groth16-keystore/ffi-tests/".to_string();
        let (proof_compressed, vk_compressed) = generate_groth16_proof_from_json_compressed(
            &load_fixture(&path, "common_circuit_data.json"),
            &load_fixture(&path, "proof_with_public_inputs.json"),
            &load_fixture(&path, "verifier_only_circuit_data.json"),
            &keystore_path,
        );

        assert!(
            !proof_compressed.is_empty(),
            "compressed proof json should not be empty"
        );
        assert!(
            !vk_compressed.is_empty(),
            "compressed vk json should not be empty"
        );
        assert!(
            !proof_compressed.starts_with("error:"),
            "compressed proof generation failed: {}",
            proof_compressed
        );
        assert!(
            !vk_compressed.starts_with("error:"),
            "compressed vk generation failed: {}",
            vk_compressed
        );
        assert!(verify_groth16_proof_compressed(
            &proof_compressed,
            &vk_compressed
        ));
    }

    #[test]
    fn generate_groth16_proof_from_json_compressed_tampered_public_input_fails_test() {
        let path = fixture_dir();
        let keystore_path = "/tmp/groth16-keystore/ffi-tests/".to_string();
        let (proof_compressed, vk_compressed) = generate_groth16_proof_from_json_compressed(
            &load_fixture(&path, "common_circuit_data.json"),
            &load_fixture(&path, "proof_with_public_inputs.json"),
            &load_fixture(&path, "verifier_only_circuit_data.json"),
            &keystore_path,
        );

        assert!(
            verify_groth16_proof_compressed(&proof_compressed, &vk_compressed),
            "sanity check failed: untampered compressed proof should verify"
        );

        let mut proof_json: Value = serde_json::from_str(&proof_compressed)
            .expect("compressed proof should be valid JSON");
        let original_public_input = proof_json["public_input_0"]
            .as_str()
            .expect("public_input_0 must be a string");
        let tampered_public_input = flip_first_hex_nibble(original_public_input);
        proof_json["public_input_0"] = Value::String(tampered_public_input);

        let tampered_proof = serde_json::to_string(&proof_json)
            .expect("tampered proof should serialize");

        assert!(
            !verify_groth16_proof_compressed(&tampered_proof, &vk_compressed),
            "tampered compressed public input must fail verification"
        );
    }

    #[test]
    fn convert_groth16_to_compressed_test() {
        let ctx = test_context();
        let (proof_compressed, vk_compressed) =
            convert_groth16_to_compressed(&ctx.proof_json, &ctx.vk_json);
        assert!(
            !proof_compressed.starts_with("error:"),
            "compressed proof conversion failed: {}",
            proof_compressed
        );
        assert!(
            !vk_compressed.starts_with("error:"),
            "compressed vk conversion failed: {}",
            vk_compressed
        );
        assert!(verify_groth16_proof_compressed(&proof_compressed, &vk_compressed));
    }

    #[test]
    fn initialize_test() {
        let ctx = test_context();
        initialize(&ctx.keystore_path);
    }

    #[test]
    fn export_solidity_verifier_test() {
        let ctx = test_context();
        let solidity = export_solidity_verifier(&ctx.keystore_path);
        assert!(
            !solidity.starts_with("error:"),
            "export_solidity_verifier returned error: {}",
            solidity
        );
        assert!(
            solidity.contains("contract"),
            "solidity verifier should contain contract declaration"
        );
    }
}
