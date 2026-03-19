package variables

import (
	"math/big"

	"github.com/zilong-dai/gnark/frontend"
	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/poseidon"
	"github.com/cf/gnark-plonky2-verifier/types"
)

func DeserializeMerkleCap(merkleCapRaw []string) FriMerkleCap {
	n := len(merkleCapRaw)
	merkleCap := make([]poseidon.BLS12381HashOut, n)
	for i := 0; i < n; i++ {
		capBigInt, _ := new(big.Int).SetString(merkleCapRaw[i], 10)
		merkleCap[i] = frontend.Variable(capBigInt)
	}
	return merkleCap
}

func DeserializeMerkleProof(merkleProofRaw struct{ Siblings []interface{} }) FriMerkleProof {
	n := len(merkleProofRaw.Siblings)
	var mp FriMerkleProof
	mp.Siblings = make([]poseidon.BLS12381HashOut, n)
	for i := 0; i < n; i++ {
		element := merkleProofRaw.Siblings[i].(struct{ Elements []uint64 })
		mp.Siblings[i] = gl.Uint64ArrayToVariableArray(element.Elements)
	}
	return mp
}

func DeserializeOpeningSet(openingSetRaw struct {
	Constants       [][]uint64
	PlonkSigmas     [][]uint64
	Wires           [][]uint64
	PlonkZs         [][]uint64
	PlonkZsNext     [][]uint64
	PartialProducts [][]uint64
	QuotientPolys   [][]uint64
}) OpeningSet {
	return OpeningSet{
		Constants:       gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Constants),
		PlonkSigmas:     gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkSigmas),
		Wires:           gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Wires),
		PlonkZs:         gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZs),
		PlonkZsNext:     gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZsNext),
		PartialProducts: gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PartialProducts),
		QuotientPolys:   gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.QuotientPolys),
	}
}

func StringArrayToHashBLS12381Array(rawHashes []string) []poseidon.BLS12381HashOut {
	hashes := []poseidon.BLS12381HashOut{}

	for i := 0; i < len(rawHashes); i++ {
		hashBigInt, _ := new(big.Int).SetString(rawHashes[i], 10)
		hashVar := frontend.Variable(hashBigInt)
		hashes = append(hashes, poseidon.BLS12381HashOut(hashVar))
	}

	return hashes
}

func DeserializeFriProof(openingProofRaw struct {
	DegreeBits             uint64
	CommitPhaseMerkleCaps [][]string
	QueryRoundProofs      []struct {
		InitialTreesProof struct {
			EvalsProofs []types.EvalProofRaw
		}
		Steps []struct {
			Evals       [][]uint64
			MerkleProof struct {
				Siblings []string
			}
		}
	}
	FinalPoly struct {
		Coeffs [][]uint64
	}
	PowWitness uint64
}) FriProof {
	var openingProof FriProof
	openingProof.PowWitness = gl.NewVariable(openingProofRaw.PowWitness)
	openingProof.FinalPoly.Coeffs = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.FinalPoly.Coeffs)

	openingProof.CommitPhaseMerkleCaps = make([]FriMerkleCap, len(openingProofRaw.CommitPhaseMerkleCaps))
	for i := 0; i < len(openingProofRaw.CommitPhaseMerkleCaps); i++ {
		openingProof.CommitPhaseMerkleCaps[i] = StringArrayToHashBLS12381Array(openingProofRaw.CommitPhaseMerkleCaps[i])
	}

	numQueryRoundProofs := len(openingProofRaw.QueryRoundProofs)
	openingProof.QueryRoundProofs = make([]FriQueryRound, numQueryRoundProofs)

	for i := 0; i < numQueryRoundProofs; i++ {
		numEvalProofs := len(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs)
		openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs = make([]FriEvalProof, numEvalProofs)
		for j := 0; j < numEvalProofs; j++ {
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].Elements = gl.Uint64ArrayToVariableArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].LeafElements)
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Siblings = StringArrayToHashBLS12381Array(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Hash)
		}

		numSteps := len(openingProofRaw.QueryRoundProofs[i].Steps)
		openingProof.QueryRoundProofs[i].Steps = make([]FriQueryStep, numSteps)
		for j := 0; j < numSteps; j++ {
			openingProof.QueryRoundProofs[i].Steps[j].Evals = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.QueryRoundProofs[i].Steps[j].Evals)
			openingProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = StringArrayToHashBLS12381Array(openingProofRaw.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings)
		}
	}

	return openingProof
}

func DeserializeFriProofFromRaw(openingProofRaw types.OpeningProof) FriProof {
	var openingProof FriProof
	openingProof.PowWitness = gl.NewVariable(openingProofRaw.PowWitness)
	openingProof.FinalPoly.Coeffs = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.FinalPoly.Coeffs)

	openingProof.CommitPhaseMerkleCaps = make([]FriMerkleCap, len(openingProofRaw.CommitPhaseMerkleCaps))
	for i := 0; i < len(openingProofRaw.CommitPhaseMerkleCaps); i++ {
		openingProof.CommitPhaseMerkleCaps[i] = StringArrayToHashBLS12381Array(openingProofRaw.CommitPhaseMerkleCaps[i])
	}

	numQueryRoundProofs := len(openingProofRaw.QueryRoundProofs)
	openingProof.QueryRoundProofs = make([]FriQueryRound, numQueryRoundProofs)

	for i := 0; i < numQueryRoundProofs; i++ {
		numEvalProofs := len(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs)
		openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs = make([]FriEvalProof, numEvalProofs)
		for j := 0; j < numEvalProofs; j++ {
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].Elements = gl.Uint64ArrayToVariableArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].LeafElements)
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Siblings = StringArrayToHashBLS12381Array(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Hash)
		}

		numSteps := len(openingProofRaw.QueryRoundProofs[i].Steps)
		openingProof.QueryRoundProofs[i].Steps = make([]FriQueryStep, numSteps)
		for j := 0; j < numSteps; j++ {
			openingProof.QueryRoundProofs[i].Steps[j].Evals = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.QueryRoundProofs[i].Steps[j].Evals)
			openingProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = StringArrayToHashBLS12381Array(openingProofRaw.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings)
		}
	}

	return openingProof
}

func DeserializeProofWithPublicInputs(raw types.ProofWithPublicInputsRaw) ProofWithPublicInputs {
	var proofWithPis ProofWithPublicInputs
	proofWithPis.Proof.WiresCap = DeserializeMerkleCap(raw.Proof.WiresCap)
	proofWithPis.Proof.PlonkZsPartialProductsCap = DeserializeMerkleCap(raw.Proof.PlonkZsPartialProductsCap)
	proofWithPis.Proof.QuotientPolysCap = DeserializeMerkleCap(raw.Proof.QuotientPolysCap)
	proofWithPis.Proof.Openings = DeserializeOpeningSet(struct {
		Constants       [][]uint64
		PlonkSigmas     [][]uint64
		Wires           [][]uint64
		PlonkZs         [][]uint64
		PlonkZsNext     [][]uint64
		PartialProducts [][]uint64
		QuotientPolys   [][]uint64
	}(raw.Proof.Openings))
	proofWithPis.Proof.OpeningProof = DeserializeFriProofFromRaw(raw.Proof.OpeningProof)
	proofWithPis.PublicInputs = gl.Uint64ArrayToVariableArray(raw.PublicInputs)

	return proofWithPis
}

func DeserializeVerifierOnlyCircuitData(raw types.VerifierOnlyCircuitDataRaw) VerifierOnlyCircuitData {
	var verifierOnlyCircuitData VerifierOnlyCircuitData
	verifierOnlyCircuitData.ConstantSigmasCap = DeserializeMerkleCap(raw.ConstantsSigmasCap)
	circuitDigestBigInt, _ := new(big.Int).SetString(raw.CircuitDigest, 10)
	circuitDigestVar := frontend.Variable(circuitDigestBigInt)
	verifierOnlyCircuitData.CircuitDigest = poseidon.BLS12381HashOut(circuitDigestVar)
	return verifierOnlyCircuitData
}
