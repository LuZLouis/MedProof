package poseidon

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type hashVectorCircuit struct {
	Input [2]frontend.Variable
	Out   frontend.Variable `gnark:",public"`
}

type resultVectorCircuit struct {
	Init  frontend.Variable
	Input [3]frontend.Variable
	Out   frontend.Variable `gnark:",public"`
}

type resultConstantCircuit struct {
	Input [3]frontend.Variable
	Out   frontend.Variable `gnark:",public"`
}

func (c *resultConstantCircuit) Define(api frontend.API) error {
	domain := new(big.Int).SetBytes([]byte("MedProof/commit/Y"))
	v, err := CircuitHash(api, []frontend.Variable{c.Input[0], c.Input[1], c.Input[2]}, domain)
	if err != nil {
		return err
	}
	api.AssertIsEqual(v, c.Out)
	return nil
}

func (c *resultVectorCircuit) Define(api frontend.API) error {
	v, err := CircuitHash(api, []frontend.Variable{c.Input[0], c.Input[1], c.Input[2]}, c.Init)
	if err != nil {
		return err
	}
	api.AssertIsEqual(v, c.Out)
	return nil
}

func (c *hashVectorCircuit) Define(api frontend.API) error {
	v, err := CircuitHash(api, []frontend.Variable{c.Input[0], c.Input[1]}, 0)
	if err != nil {
		return err
	}
	api.AssertIsEqual(v, c.Out)
	return nil
}

func TestPoseidonNonzeroDomainVector(t *testing.T) {
	domain := new(big.Int).SetBytes([]byte("MedProof/commit/Y"))
	inputs := []*big.Int{big.NewInt(123), big.NewInt(14), big.NewInt(12)}
	want, err := Native(inputs, domain)
	if err != nil {
		t.Fatal(err)
	}
	assignment := &resultVectorCircuit{Init: domain, Input: [3]frontend.Variable{123, 14, 12}, Out: want}
	if err := test.IsSolved(&resultVectorCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	constantAssignment := &resultConstantCircuit{Input: [3]frontend.Variable{123, 14, 12}, Out: want}
	if err := test.IsSolved(&resultConstantCircuit{}, constantAssignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func TestPoseidonNativeAndCircuitVector(t *testing.T) {
	want := "7853200120776062878684798364095072458815029376092732009249414926327459813530"
	native, err := Native([]*big.Int{big.NewInt(1), big.NewInt(2)}, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	if native.String() != want {
		t.Fatalf("native vector mismatch: %s", native)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &hashVectorCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	witness := &hashVectorCircuit{Input: [2]frontend.Variable{1, 2}, Out: native}
	if err := test.IsSolved(&hashVectorCircuit{}, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	_ = ccs
}
