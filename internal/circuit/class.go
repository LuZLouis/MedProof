package circuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"medproof/internal/poseidon"
)

// ClassCircuit proves one hidden result per complete supported ingredient set.
// Class-to-product expansion is public and independently reconstructed by the auditor.
type ClassCircuit struct {
	CA      frontend.Variable     `gnark:",public"`
	CY      frontend.Variable     `gnark:",public"`
	DQ      frontend.Variable     `gnark:",public"`
	Classes [][]frontend.Variable `gnark:",public"`

	A    []frontend.Variable
	RhoA frontend.Variable
	C    []frontend.Variable
	Z    []frontend.Variable
	RhoY frontend.Variable
}

func (c *ClassCircuit) Define(api frontend.API) error {
	if len(c.A) == 0 || len(c.Classes) == 0 || len(c.C) != len(c.Classes) || len(c.Z) != len(c.Classes) {
		return fmt.Errorf("inconsistent class circuit dimensions")
	}
	ca, err := privateSetAndCommit(api, c.A, c.RhoA)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.CA, ca)
	for k := range c.Classes {
		if len(c.Classes[k]) == 0 {
			return fmt.Errorf("class %d has no ingredient slots", k)
		}
		factors := make([]frontend.Variable, 0, len(c.Classes[k])*len(c.A))
		for _, x := range c.Classes[k] {
			api.ToBinary(x, CodeWidth)
			api.AssertIsDifferent(x, 0)
			for _, a := range c.A {
				factors = append(factors, api.Sub(x, a))
			}
		}
		product := productVars(api, factors)
		api.AssertIsBoolean(c.C[k])
		api.AssertIsEqual(api.Mul(product, c.Z[k]), c.C[k])
		api.AssertIsEqual(api.Mul(product, api.Sub(1, c.C[k])), 0)
	}
	bitpack := packBits(api, c.C)
	cy, err := poseidon.CircuitHash(api, []frontend.Variable{c.DQ, bitpack, c.RhoY}, domainResult)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.CY, cy)
	return nil
}
