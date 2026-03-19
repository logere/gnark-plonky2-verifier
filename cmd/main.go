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
	"fmt"
	"os"

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

//export VerifyGroth16Proof
func VerifyGroth16Proof(proofString *C.char, vkString *C.char) *C.char {
	return C.CString(worker.VerifyProof(C.GoString(proofString), C.GoString(vkString)))
}

//export Initialize
func Initialize(keyPath *C.char) {
	worker.Initialize(C.GoString(keyPath))
}

func main() {
	path := "/tmp/proof"

	common_circuit_data, _ := os.ReadFile(path + "/common_circuit_data.json")
	proof_with_public_inputs, _ := os.ReadFile(path + "/proof_with_public_inputs.json")
	verifier_only_circuit_data, _ := os.ReadFile(path + "/verifier_only_circuit_data.json")

	proof_city, vk_city := worker.GenerateProof(string(common_circuit_data), string(proof_with_public_inputs), string(verifier_only_circuit_data), "/tmp/groth16-keystore/0/")
	fmt.Println("proof city", proof_city)
	fmt.Println("vk city", vk_city)
}
