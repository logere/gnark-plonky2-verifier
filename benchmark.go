package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/backend/witness"
	"github.com/zilong-dai/gnark/constraint"
	csbls12381 "github.com/zilong-dai/gnark/constraint/bls12-381"
	csolver "github.com/zilong-dai/gnark/constraint/solver"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gnark/frontend/cs/scs"
	"github.com/zilong-dai/gnark/profile"
	"github.com/rs/zerolog"
)

func runBenchmark(plonky2Circuit string, proofSystem string, profileCircuit bool, dummy bool, saveArtifacts bool) {
	commonCircuitData := types.ReadCommonCircuitData("testdata/" + plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	var p *profile.Profile
	if profileCircuit {
		p = profile.Start()
	}

	var builder frontend.NewBuilder
	if proofSystem == "plonk" {
		builder = scs.NewBuilder
	} else if proofSystem == "groth16" {
		builder = r1cs.NewBuilder
	} else {
		fmt.Println("Please provide a valid proof system to benchmark, we only support plonk and groth16")
		os.Exit(1)
	}

	r1cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), builder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	if profileCircuit {
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}

	if proofSystem == "plonk" {
		plonkProof(r1cs, plonky2Circuit, dummy, saveArtifacts)
	} else if proofSystem == "groth16" {
		groth16Proof(r1cs, plonky2Circuit, dummy, saveArtifacts)
	} else {
		panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
	}
}

func plonkProof(r1cs constraint.ConstraintSystem, circuitName string, dummy bool, saveArtifacts bool) {

}

func groth16Proof(r1cs constraint.ConstraintSystem, circuitName string, dummy bool, saveArtifacts bool) {
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + circuitName + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + circuitName + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}
	// Don't serialize the circuit for now, since it takes up too much memory
	// if saveArtifacts {
	// 	fR1CS, _ := os.Create("circuit")
	// 	r1cs.WriteTo(fR1CS)
	// 	fR1CS.Close()
	// }

	fmt.Println("Running circuit setup", time.Now())
	if dummy {
		fmt.Println("Using dummy setup")
		pk, err = groth16.DummySetup(r1cs)
	} else {
		fmt.Println("Using real setup")
		pk, vk, err = groth16.Setup(r1cs)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if saveArtifacts {
		fPK, _ := os.Create("proving.key")
		pk.WriteTo(fPK)
		fPK.Close()

		if vk != nil {
			fVK, _ := os.Create("verifying.key")
			vk.WriteTo(fVK)
			fVK.Close()
		}

		fSolidity, _ := os.Create("proof.sol")
		err = vk.ExportSolidity(fSolidity)
	}

	fmt.Println("Generating witness", time.Now())
	wit, _ := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err := debugUnsatisfiedConstraint(r1cs, wit); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	publicWitness, _ := witness.Witness(wit).Public()
	if saveArtifacts {
		fWitness, _ := os.Create("witness")
		wit.WriteTo(fWitness)
		fWitness.Close()
	}

	fmt.Println("Creating proof", time.Now())
	proof, err := groth16.Prove(r1cs, pk, witness.Witness(wit))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if saveArtifacts {
		fProof, _ := os.Create("proof.proof")
		proof.WriteTo(fProof)
		fProof.Close()
	}

	if vk == nil {
		fmt.Println("vk is nil, means you're using dummy setup and we skip verification of proof")
		return
	}

	fmt.Println("Verifying proof", time.Now())
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var (
		a [2]*big.Int
		b [2][2]*big.Int
		c [2]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	println("a[0] is ", a[0].String())
	println("a[1] is ", a[1].String())

	println("b[0][0] is ", b[0][0].String())
	println("b[0][1] is ", b[0][1].String())
	println("b[1][0] is ", b[1][0].String())
	println("b[1][1] is ", b[1][1].String())

	println("c[0] is ", c[0].String())
	println("c[1] is ", c[1].String())

}

func debugUnsatisfiedConstraint(ccs constraint.ConstraintSystem, wit witness.Witness) error {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger().Level(zerolog.DebugLevel)
	if err := ccs.IsSolved(wit, csolver.WithLogger(logger)); err != nil {
		fmt.Printf("IsSolved failed: %v\n", err)
		cid := -1
		switch e := err.(type) {
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

func main() {
	plonky2Circuit := flag.String("plonky2-circuit", "step", "plonky2 circuit to benchmark")
	proofSystem := flag.String("proof-system", "plonk", "proof system to benchmark")
	profileCircuit := flag.Bool("profile", true, "profile the circuit")
	dummySetup := flag.Bool("dummy", true, "use dummy setup")
	saveArtifacts := flag.Bool("save", false, "save circuit artifacts")

	flag.Parse()

	if plonky2Circuit == nil || *plonky2Circuit == "" {
		fmt.Println("Please provide a plonky2 circuit to benchmark")
		os.Exit(1)
	}

	fmt.Printf("Running benchmark for %s circuit with proof system %s\n", *plonky2Circuit, *proofSystem)
	fmt.Printf("Profiling: %t, DummySetup: %t, SaveArtifacts: %t\n", *profileCircuit, *dummySetup, *saveArtifacts)

	runBenchmark(*plonky2Circuit, *proofSystem, *profileCircuit, *dummySetup, *saveArtifacts)
}
