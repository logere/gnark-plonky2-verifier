package main

/*
#include <stdlib.h> // Include C standard library, if necessary
#include <string.h>
typedef struct {
    char* proof;
    char* vk;
} Groth16ProofWithVK;
*/
import "C"
import (
	"bytes"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkgroth16 "github.com/zilong-dai/gnark/backend/groth16"

	"github.com/cf/gnark-plonky2-verifier/worker"
)

type Groth16ProofWithVK struct {
	Proof string
	Vk    string
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(common_circuit_data *C.char, proof_with_public_inputs *C.char, verifier_only_circuit_data *C.char, keystore_path *C.char) *C.Groth16ProofWithVK {
	proof_str, vk_str := worker.GenerateProof(C.GoString(common_circuit_data), C.GoString(proof_with_public_inputs), C.GoString(verifier_only_circuit_data), C.GoString(keystore_path))

	cProofWithVk := (*C.Groth16ProofWithVK)(C.malloc(C.sizeof_Groth16ProofWithVK))
	cProofWithVk.proof = C.CString(proof_str)
	cProofWithVk.vk = C.CString(vk_str)
	return cProofWithVk
}

//export GenerateGroth16ProofFromJson
func GenerateGroth16ProofFromJson(common_circuit_data_json *C.char, proof_with_public_inputs_json *C.char, verifier_only_circuit_data_json *C.char, keystore_path *C.char) *C.Groth16ProofWithVK {
	proof_str, vk_str := worker.GenerateProof(C.GoString(common_circuit_data_json), C.GoString(proof_with_public_inputs_json), C.GoString(verifier_only_circuit_data_json), C.GoString(keystore_path))

	cProofWithVk := (*C.Groth16ProofWithVK)(C.malloc(C.sizeof_Groth16ProofWithVK))
	cProofWithVk.proof = C.CString(proof_str)
	cProofWithVk.vk = C.CString(vk_str)
	return cProofWithVk
}

//export VerifyGroth16Proof
func VerifyGroth16Proof(proofString *C.char, vkString *C.char) C.int {
	if worker.VerifyProof(C.GoString(proofString), C.GoString(vkString)) {
		return 1
	}
	return 0
}

//export Initialize
func Initialize(keyPath *C.char) {
	worker.Initialize(C.GoString(keyPath))
}

//export ExportSolidityVerifier
func ExportSolidityVerifier(keystorePath *C.char) *C.char {
	vk, err := worker.ReadVerifyingKey(ecc.BN254, C.GoString(keystorePath)+"/"+worker.VK_PATH)
	if err != nil {
		return C.CString(fmt.Sprintf("error: %v", err))
	}
	var buf bytes.Buffer
	if err := vk.(gnarkgroth16.VerifyingKey).ExportSolidity(&buf); err != nil {
		return C.CString(fmt.Sprintf("error: %v", err))
	}
	return C.CString(buf.String())
}

func main() {
	path := "/tmp/proof"

	common_circuit_data, _ := os.ReadFile(path + "/common_circuit_data.json")
	proof_with_public_inputs, _ := os.ReadFile(path + "/proof_with_public_inputs.json")
	verifier_only_circuit_data, _ := os.ReadFile(path + "/verifier_only_circuit_data.json")

	proof, vk := worker.GenerateProof(string(common_circuit_data), string(proof_with_public_inputs), string(verifier_only_circuit_data), "/tmp/groth16-keystore/0/")
	fmt.Println("proof", proof)
	fmt.Println("vk", vk)

	verifyResult := worker.VerifyProof(proof, vk)
	fmt.Println("verify_result", verifyResult)
}
