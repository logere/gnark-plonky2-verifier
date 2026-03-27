package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/backend/witness"
	"github.com/zilong-dai/gnark/constraint"
)

func Sha256(data []byte) {
	h := sha256.New()
	h.Write([]byte(data))
	h.Sum(nil)
}

func WriteProof(proof groth16.Proof, path string) error {
	if proof == nil {
		return fmt.Errorf("proof is not initialized")
	}

	proofFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer proofFile.Close()

	if _, err := proof.WriteTo(proofFile); err != nil {
		return fmt.Errorf("failed to write proof to file: %w", err)
	}

	return nil
}

func ReadProof(CURVE_ID ecc.ID, path string) (groth16.Proof, error) {
	proof := groth16.NewProof(CURVE_ID)
	proofFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	defer proofFile.Close()

	_, err = proof.ReadFrom(proofFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof: %w", err)
	}

	return proof, nil
}

func WritePublicInputs(witness witness.Witness, path string) error {
	if witness == nil {
		return fmt.Errorf("witness is not initialized")
	}

	publicinputsFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer publicinputsFile.Close()

	if n, err := witness.WriteTo(publicinputsFile); err != nil {
		fmt.Println(n/32, " witness len ", n)
		return fmt.Errorf("failed to write proof to file: %w", err)
	}

	return nil
}

func ReadPublicInputs(CURVE_ID ecc.ID, path string) (witness.Witness, error) {
	witness, err := witness.New(CURVE_ID.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	publicinputsFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open public inputs file: %w", err)
	}
	defer publicinputsFile.Close()

	_, err = witness.ReadFrom(publicinputsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read public inputs: %w", err)
	}

	return witness, nil
}

func WriteProvingKey(pk groth16.ProvingKey, path string) error {
	if pk == nil {
		return fmt.Errorf("pk is not initialized")
	}

	pkFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer pkFile.Close()

	if _, err := pk.WriteTo(pkFile); err != nil {
		return fmt.Errorf("failed to write pk to file: %w", err)
	}

	return nil
}

func ReadProvingKey(CURVE_ID ecc.ID, path string) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(CURVE_ID)
	pkFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	defer pkFile.Close()

	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read pk: %w", err)
	}

	return pk, nil
}

func WriteVerifyingKey(vk groth16.VerifyingKey, path string) error {
	if vk == nil {
		return fmt.Errorf("vk is not initialized")
	}

	vkFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer vkFile.Close()

	if _, err := vk.WriteTo(vkFile); err != nil {
		return fmt.Errorf("failed to write vk to file: %w", err)
	}

	return nil
}

func ReadVerifyingKey(CURVE_ID ecc.ID, path string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(CURVE_ID)
	vkFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	defer vkFile.Close()

	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vk: %w", err)
	}

	return vk, nil
}

func ReadCircuit(CURVE_ID ecc.ID, path string) (constraint.ConstraintSystem, error) {
	r1cs := groth16.NewCS(CURVE_ID)
	if r1cs == nil {
		return nil, fmt.Errorf("r1cs is not initialized")
	}

	circuitFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open circuit file: %w", err)
	}
	defer circuitFile.Close()

	_, err = r1cs.ReadFrom(circuitFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read circuit: %w", err)
	}

	return r1cs, nil
}

func WriteCircuit(r1cs constraint.ConstraintSystem, path string) error {
	if r1cs == nil {
		return fmt.Errorf("r1cs is not initialized")
	}

	circuitFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to circuit file: %w", err)
	}
	defer circuitFile.Close()

	if _, err := r1cs.WriteTo(circuitFile); err != nil {
		return fmt.Errorf("failed to write circuit to file: %w", err)
	}

	return nil
}

func CheckKeysExist(path string) bool {
	files := []string{
		CIRCUIT_PATH,
		VK_PATH,
		PK_PATH,
	}

	for _, file := range files {
		path := filepath.Join(path, file)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return false
			} else {
				return false
			}
		}
	}

	return true
}

func CheckVKeysExist(path string) bool {

	path = filepath.Join(path, VK_PATH)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		} else {
			return false
		}
	}

	return true
}

func DeSerializeG1MCL(g1s string) (*curve.G1Affine, error) {
	g1Bytes, err := hex.DecodeString(reverseHexString(g1s))
	if err != nil {
		return nil, fmt.Errorf("failed to decode g1 hex string: %w", err)
	}

	oddFlag := false
	if g1Bytes[0]&0x80 == 0x80 {
		oddFlag = true
	}

	g1Bytes[0] &= 0x7f

	g1 := new(curve.G1Affine)

	var X, YSquared, Y, bCurveCoeff fp.Element

	X.SetBytes(g1Bytes[:])

	// BN254 G1 curve equation: y^2 = x^3 + 3
	bCurveCoeff.SetUint64(3)

	YSquared.Square(&X).Mul(&YSquared, &X)
	YSquared.Add(&YSquared, &bCurveCoeff)
	if Y.Sqrt(&YSquared) == nil {
		return nil, errors.New("invalid compressed coordinate: square root doesn't exist")
	}

	if oddFlag != isOddFp(&Y) {
		Y.Neg(&Y)
	}

	g1.X = X
	g1.Y = Y

	return g1, nil
}

func DeSerializeG2MCL(g2a0, g2a1 string) (*curve.G2Affine, error) {
	g2a0Bytes, err := hex.DecodeString(reverseHexString(g2a0))
	if err != nil {
		return nil, fmt.Errorf("failed to decode g2 hex string: %w", err)
	}
	g2a1Bytes, err := hex.DecodeString(reverseHexString(g2a1))
	if err != nil {
		return nil, fmt.Errorf("failed to decode g2 hex string: %w", err)
	}

	oddFlag := false
	if g2a1Bytes[0]&0x80 == 0x80 {
		oddFlag = true
	}

	g2a1Bytes[0] &= 0x7f

	g2 := new(curve.G2Affine)

	g2.X.A0.SetBytes(g2a0Bytes)
	g2.X.A1.SetBytes(g2a1Bytes)

	var YSquared, Y, bTwistCurveCoeff curve.E2

	// BN254 twist curve coefficient used by gnark:
	// y^2 = x^3 + bTwist, where
	// bTwist = (19485874751759354771024239261021720505790618469301721065564631296452457478373,
	//           266929791119991161246907387137283842545076965332900288569378510910307636690)
	if _, err := bTwistCurveCoeff.A0.SetString("19485874751759354771024239261021720505790618469301721065564631296452457478373"); err != nil {
		return nil, fmt.Errorf("failed to parse bn254 twist coefficient A0: %w", err)
	}
	if _, err := bTwistCurveCoeff.A1.SetString("266929791119991161246907387137283842545076965332900288569378510910307636690"); err != nil {
		return nil, fmt.Errorf("failed to parse bn254 twist coefficient A1: %w", err)
	}

	YSquared.Square(&g2.X).Mul(&YSquared, &g2.X)
	YSquared.Add(&YSquared, &bTwistCurveCoeff)
	if YSquared.Legendre() == -1 {
		return nil, errors.New("invalid compressed coordinate: square root doesn't exist")
	}
	Y.Sqrt(&YSquared)

	if oddFlag != isOddFp(&Y.A0) {
		Y.Neg(&Y)
	}
	g2.Y = Y

	return g2, nil
}

func isOddFp(x *fp.Element) bool {
	return x.BigInt(big.NewInt(0)).Bit(0) == 1
}

func reverseHexString(hexStr string) string {
	reversed := make([]byte, len(hexStr))
	for i := 0; i < len(hexStr); i += 2 {
		reversed[i] = hexStr[len(hexStr)-i-2]
		reversed[i+1] = hexStr[len(hexStr)-i-1]
	}
	return string(reversed)
}
