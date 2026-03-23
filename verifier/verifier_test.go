package verifier_test

import (
	"math/big"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/test"
)

type CRVerifierCircuit struct {
	PublicInputs            []frontend.Variable               `gnark:",public"`
	Proof                   variables.Proof                   `gnark:",secret"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:",secret"`

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

	api.Println("PublicInputs[0]", c.PublicInputs[0])
	api.Println("blockStateHashAcc", blockStateHashAcc)
	api.Println("PublicInputs[1]", c.PublicInputs[1])
	api.Println("sighashAcc", sighashAcc)
	api.AssertIsEqual(c.PublicInputs[0], blockStateHashAcc)
	api.AssertIsEqual(c.PublicInputs[1], sighashAcc)

	verifierChip.Verify(c.Proof, c.OriginalPublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

func TestStepVerifier(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		path := "/tmp/plonky2_proof/0"
		commonCircuitData := types.ReadCommonCircuitData(path + "/common_circuit_data.json")

		rawProofWithPis := types.ReadProofWithPublicInputs(path + "/proof_with_public_inputs.json")
		proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)
		rawVerifierOnlyCircuitData := types.ReadVerifierOnlyCircuitData(path + "/verifier_only_circuit_data.json")
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(rawVerifierOnlyCircuitData)

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
		sighash := frontend.Variable(sighashAcc)

		circuit := CRVerifierCircuit{
			PublicInputs:            make([]frontend.Variable, 2),
			Proof:                   proofWithPis.Proof,
			OriginalPublicInputs:    proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		witness := CRVerifierCircuit{
			PublicInputs:            []frontend.Variable{blockStateHash, sighash},
			Proof:                   circuit.Proof,
			OriginalPublicInputs:    circuit.OriginalPublicInputs,
			VerifierOnlyCircuitData: circuit.VerifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
	testCase()
}
