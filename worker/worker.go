package worker

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/GopherJ/doge-covenant/serialize"
	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/rs/zerolog"
	"github.com/zilong-dai/gnark/backend/groth16"
	groth16_bn254 "github.com/zilong-dai/gnark/backend/groth16/bn254"
	"github.com/zilong-dai/gnark/backend/witness"
	"github.com/zilong-dai/gnark/constraint"
	csbls12381 "github.com/zilong-dai/gnark/constraint/bls12-381"
	csbn254 "github.com/zilong-dai/gnark/constraint/bn254"
	csolver "github.com/zilong-dai/gnark/constraint/solver"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type PreparedCircuit struct {
	PKey *groth16_bn254.ProvingKey
	VKey *groth16_bn254.VerifyingKey
	CCS  *constraint.ConstraintSystem
}

var prepCircuit1 = PreparedCircuit{
	PKey: nil,
	VKey: nil,
	CCS:  nil,
}

func Initialize(keystore_path string) {
	fmt.Println("Initializing...", time.Now().Format("2006-01-02 15:04:05"))
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var ccs constraint.ConstraintSystem
	var err error
	if !CheckKeysExist(keystore_path) {
		panic("Initializing Keys not exist")
	}

	ccs, err = ReadCircuit(ecc.BN254, filepath.Join(keystore_path, CIRCUIT_PATH))
	if err != nil {
		panic(err)
	}
	vk, err = ReadVerifyingKey(ecc.BN254, filepath.Join(keystore_path, VK_PATH))
	if err != nil {
		panic(err)
	}
	pk, err = ReadProvingKey(ecc.BN254, filepath.Join(keystore_path, PK_PATH))
	if err != nil {
		panic(err)
	}

	prepCircuit1.CCS = &ccs
	prepCircuit1.PKey = pk.(*groth16_bn254.ProvingKey)
	prepCircuit1.VKey = vk.(*groth16_bn254.VerifyingKey)
	fmt.Println("Initializing End...", time.Now().Format("2006-01-02 15:04:05"))
}

type CRVerifierCircuit struct {
	PublicInputs            []frontend.Variable               `gnark:",public"`
	Proof                   variables.Proof                   `gnark:",secret"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	OriginalPublicInputs []gl.Variable `gnark:",secret"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData `gnark:",secret"`
}

func (c *CRVerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	if len(c.PublicInputs) != 2 {
		panic("invalid public inputs, should contain 2 BN254 elements")
	}
	if len(c.OriginalPublicInputs) != 512 {
		panic("invalid original public inputs, should contain 512 goldilocks elements")
	}

	two := big.NewInt(2)

	blockStateHashAcc := frontend.Variable(0)
	sighashAcc := frontend.Variable(0)
	for i := 255; i >= 0; i-- {
		blockStateHashAcc = api.Mul(blockStateHashAcc, two)
		blockStateHashAcc = api.Add(blockStateHashAcc, c.OriginalPublicInputs[i].Limb)
	}
	for i := 511; i >= 256; i-- {
		sighashAcc = api.Mul(sighashAcc, two)
		sighashAcc = api.Add(sighashAcc, c.OriginalPublicInputs[i].Limb)
	}

	api.AssertIsEqual(c.PublicInputs[0], blockStateHashAcc)
	api.AssertIsEqual(c.PublicInputs[1], sighashAcc)

	verifierChip.Verify(c.Proof, c.OriginalPublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

func initKeyStorePath(keystore_path string) {
	_, err := os.Stat(keystore_path)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(keystore_path, os.ModePerm)
		}
	}
}

func GenerateProof(common_circuit_data string, proof_with_public_inputs string, verifier_only_circuit_data string, keystore_path string) (string, string) {
	initKeyStorePath(keystore_path)

	commonCircuitData := types.ReadCommonCircuitDataRaw(common_circuit_data)
	verifierOnlyCircuitDataRaw := types.ReadVerifierOnlyCircuitDataRaw(verifier_only_circuit_data)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitDataRaw)

	rawProofWithPis := types.ReadProofWithPublicInputsRaw(proof_with_public_inputs)
	proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)

	two := big.NewInt(2)

	blockStateHashAcc := big.NewInt(0)
	sighashAcc := big.NewInt(0)
	for i := 255; i >= 0; i-- {
		blockStateHashAcc = new(big.Int).Mul(blockStateHashAcc, two)
		blockStateHashAcc = new(big.Int).Add(blockStateHashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	for i := 511; i >= 256; i-- {
		sighashAcc = new(big.Int).Mul(sighashAcc, two)
		sighashAcc = new(big.Int).Add(sighashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	blockStateHash := frontend.Variable(blockStateHashAcc)
	fmt.Println("blockStateHash", blockStateHash)
	sighash := frontend.Variable(sighashAcc)
	fmt.Println("sighash", sighash)

	circuit := CRVerifierCircuit{
		PublicInputs:            make([]frontend.Variable, 2),
		Proof:                   proofWithPis.Proof,
		OriginalPublicInputs:    proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	assignment := CRVerifierCircuit{
		PublicInputs:            []frontend.Variable{blockStateHash, sighash},
		Proof:                   circuit.Proof,
		OriginalPublicInputs:    circuit.OriginalPublicInputs,
		VerifierOnlyCircuitData: circuit.VerifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	// NewWitness() must be called before Compile() to avoid gnark panicking.
	// ref: https://github.com/Consensys/gnark/issues/1038
	wit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	cs, pk, vk, err := Setup(&circuit, keystore_path)
	if err != nil {
		panic(err)
	}

	if err := debugUnsatisfiedConstraint(*cs, wit); err != nil {
		panic(err)
	}

	var proof groth16.Proof
	var publicWitness witness.Witness
	var retries = 0

	for {
		proof, err = groth16.Prove(*cs, pk, wit)
		if err != nil {
			panic(err)
		}

		publicWitness, err = wit.Public()
		if err != nil {
			panic(err)
		}

		err = groth16.Verify(proof, vk, publicWitness)
		if err == nil {
			break
		}
		if retries > 5 {
			panic(err)
		}
		fmt.Println("generated bad proof, retrying...")
		retries += 1
	}

	bnProof := proof.(*groth16_bn254.Proof)
	bnVk := vk
	bnWitness := publicWitness.Vector().(fr.Vector)

	original_proof_bytes, err := json.Marshal(&G16ProofWithPublicInputs{
		Proof:        bnProof,
		PublicInputs: publicWitness,
	})
	if err != nil {
		panic(err)
	}
	var g16VerifyingKey = G16VerifyingKey{
		VK: vk,
	}
	original_vk_bytes, err := json.Marshal(g16VerifyingKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("proofString", string(original_proof_bytes))
	fmt.Println("vkString", string(original_vk_bytes))

	proof_city, err := serialize.ToJsonCityProof(bnProof, bnWitness)
	if err != nil {
		panic(err)
	}
	proof_bytes, err := json.Marshal(&proof_city)
	if err != nil {
		panic(err)
	}
	vk_city, err := serialize.ToJsonCityVK(bnVk)
	if err != nil {
		panic(err)
	}
	vk_bytes, err := json.Marshal(&vk_city)
	if err != nil {
		panic(err)
	}

	return string(proof_bytes), string(vk_bytes)

}

func debugUnsatisfiedConstraint(ccs constraint.ConstraintSystem, wit witness.Witness) error {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger().Level(zerolog.DebugLevel)
	if err := ccs.IsSolved(wit, csolver.WithLogger(logger)); err != nil {
		fmt.Printf("IsSolved failed: %v\n", err)
		cid := -1
		switch e := err.(type) {
		case *csbn254.UnsatisfiedConstraintError:
			cid = e.CID
		case *csbls12381.UnsatisfiedConstraintError:
			cid = e.CID
		}
		if cid >= 0 {
			if r1cs, ok := ccs.(constraint.R1CS); ok {
				it := r1cs.GetR1CIterator()
				idx := 0
				for {
					r1c := it.Next()
					if r1c == nil {
						break
					}
					if idx == cid {
						fmt.Printf("Unsatisfied constraint #%d: %s\n", cid, r1c.String(r1cs))
						break
					}
					idx++
				}
			}
		}
		return err
	}
	return nil
}

func VerifyProof(proofString string, vkString string) string {
	var cityProof serialize.CityGroth16ProofData
	var cityVk serialize.CityGroth16VerifierData

	if err := json.Unmarshal([]byte(proofString), &cityProof); err != nil {
		fmt.Println(err)
		return "false"
	}

	g16ProofWithPublicInputs, err := FromCityProof(cityProof)
	if err != nil {
		fmt.Println(err)
		return "false"
	}

	if err := json.Unmarshal([]byte(vkString), &cityVk); err != nil {
		fmt.Println(err)
		return "false"
	}
	g16VerifyingKey, err := FromCityVk(cityVk)
	if err != nil {
		fmt.Println(err)
		return "false"
	}

	if err := groth16.Verify(g16ProofWithPublicInputs.Proof, g16VerifyingKey.VK, g16ProofWithPublicInputs.PublicInputs); err != nil {
		fmt.Println(err)
		return "false"
	}
	return "true"
}

func Setup(circuit *CRVerifierCircuit, keystore_path string) (*constraint.ConstraintSystem, *groth16_bn254.ProvingKey, *groth16_bn254.VerifyingKey, error) {
	if prepCircuit1.CCS != nil && prepCircuit1.PKey != nil && prepCircuit1.VKey != nil {
		return prepCircuit1.CCS, prepCircuit1.PKey, prepCircuit1.VKey, nil
	}
	fmt.Println("you have to initialize all the keys first")
	if CheckKeysExist(keystore_path) {
		ccs, err := ReadCircuit(ecc.BN254, filepath.Join(keystore_path, CIRCUIT_PATH))
		if err != nil {
			return nil, nil, nil, err
		}
		vk, err := ReadVerifyingKey(ecc.BN254, filepath.Join(keystore_path, VK_PATH))
		if err != nil {
			return nil, nil, nil, err
		}
		pk, err := ReadProvingKey(ecc.BN254, filepath.Join(keystore_path, PK_PATH))
		if err != nil {
			return nil, nil, nil, err
		}
		prepCircuit1.CCS = &ccs
		prepCircuit1.PKey = pk.(*groth16_bn254.ProvingKey)
		prepCircuit1.VKey = vk.(*groth16_bn254.VerifyingKey)
	} else {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			return nil, nil, nil, err
		}

		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			return nil, nil, nil, err
		}

		if err := WriteCircuit(ccs, keystore_path+CIRCUIT_PATH); err != nil {
			return nil, nil, nil, err
		}

		if err := WriteVerifyingKey(vk, keystore_path+VK_PATH); err != nil {
			return nil, nil, nil, err
		}

		if err := WriteProvingKey(pk, keystore_path+PK_PATH); err != nil {
			return nil, nil, nil, err
		}
		prepCircuit1.CCS = &ccs
		prepCircuit1.PKey = pk.(*groth16_bn254.ProvingKey)
		prepCircuit1.VKey = vk.(*groth16_bn254.VerifyingKey)
	}

	return prepCircuit1.CCS, prepCircuit1.PKey, prepCircuit1.VKey, nil
}
