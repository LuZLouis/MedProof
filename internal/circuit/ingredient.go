package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"medproof/internal/poseidon"
)

const (
	CodeWidth = 16
	PackWidth = 15
	PublicPad = (1 << CodeWidth) - 1
)

var (
	domainAlert  = mustBig("26336515141831658000777440552895363952449") // ASCII MedProof/commit/A
	domainResult = mustBig("26336515141831658000777440552895363952473") // ASCII MedProof/commit/Y
)

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad field constant")
	}
	return v
}

func sumVars(api frontend.API, terms []frontend.Variable) frontend.Variable {
	if len(terms) == 1 {
		return terms[0]
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

func productVars(api frontend.API, terms []frontend.Variable) frontend.Variable {
	if len(terms) == 1 {
		return terms[0]
	}
	return api.Mul(terms[0], terms[1], terms[2:]...)
}

// IngredientCircuit proves hidden per-ingredient and per-product results.
// Slice lengths are fixed in each registered profile's circuit template.
type IngredientCircuit struct {
	CA      frontend.Variable   `gnark:",public"`
	CY      frontend.Variable   `gnark:",public"`
	DQ      frontend.Variable   `gnark:",public"`
	X       []frontend.Variable `gnark:",public"`
	R       []frontend.Variable `gnark:",public"`
	Support []frontend.Variable `gnark:",public"`

	A    []frontend.Variable
	RhoA frontend.Variable
	B    []frontend.Variable
	Z    []frontend.Variable
	M    [][]frontend.Variable
	Y    []frontend.Variable
	V    []frontend.Variable
	RhoY frontend.Variable
}

func poseidonCommit(api frontend.API, input []frontend.Variable, domain frontend.Variable) (frontend.Variable, error) {
	return poseidon.CircuitHash(api, input, domain)
}

func privateSetAndCommit(api frontend.API, a []frontend.Variable, rho frontend.Variable) (frontend.Variable, error) {
	if len(a) == 0 {
		return nil, fmt.Errorf("empty alert capacity")
	}
	packed := make([]frontend.Variable, (len(a)+PackWidth-1)/PackWidth)
	for k := range packed {
		terms := make([]frontend.Variable, 0, PackWidth)
		for j := 0; j < PackWidth && k*PackWidth+j < len(a); j++ {
			idx := k*PackWidth + j
			api.ToBinary(a[idx], CodeWidth)
			api.AssertIsDifferent(a[idx], PublicPad)
			if idx > 0 {
				prevZero := api.IsZero(a[idx-1])
				curZero := api.IsZero(a[idx])
				api.AssertIsEqual(api.Mul(prevZero, api.Sub(1, curZero)), 0) // zero padding is a suffix
				bothReal := api.Mul(api.Sub(1, prevZero), api.Sub(1, curZero))
				api.AssertIsEqual(api.Mul(bothReal, api.Add(api.Cmp(a[idx-1], a[idx]), 1)), 0) // strict order for real codes
			}
			weight := 1 << (CodeWidth * j)
			terms = append(terms, api.Mul(a[idx], weight))
		}
		packed[k] = sumVars(api, terms)
	}
	input := append(packed, rho)
	return poseidonCommit(api, input, domainAlert)
}

func packBits(api frontend.API, bits []frontend.Variable) frontend.Variable {
	terms := make([]frontend.Variable, len(bits))
	for i := range bits {
		terms[i] = api.Mul(bits[i], 1<<i)
	}
	return sumVars(api, terms)
}

func (c *IngredientCircuit) Define(api frontend.API) error {
	if len(c.X) == 0 || len(c.A) == 0 || len(c.M) != len(c.R) || len(c.Support) != len(c.R) || len(c.Y) != len(c.R) || len(c.V) != len(c.R) || len(c.B) != len(c.X) || len(c.Z) != len(c.X) {
		return fmt.Errorf("inconsistent ingredient circuit dimensions")
	}
	for j := range c.M {
		if len(c.M[j]) != len(c.X) {
			return fmt.Errorf("row %d incidence width mismatch", j)
		}
	}
	ca, err := privateSetAndCommit(api, c.A, c.RhoA)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.CA, ca)

	for i := range c.X {
		api.ToBinary(c.X[i], CodeWidth)
		api.AssertIsDifferent(c.X[i], 0)
		factors := make([]frontend.Variable, len(c.A))
		for r := range c.A {
			factors[r] = api.Sub(c.X[i], c.A[r])
		}
		product := productVars(api, factors)
		api.AssertIsEqual(api.Mul(product, c.Z[i]), c.B[i])
		api.AssertIsEqual(api.Mul(product, api.Sub(1, c.B[i])), 0)
	}

	for j := range c.R {
		maskBits := make([]frontend.Variable, len(c.X))
		matchTerms := make([]frontend.Variable, len(c.X))
		for i := range c.X {
			api.AssertIsBoolean(c.M[j][i])
			maskBits[i] = c.M[j][i]
			matchTerms[i] = api.Mul(c.M[j][i], api.Sub(1, c.B[i]))
		}
		api.AssertIsEqual(c.R[j], packBits(api, maskBits))
		api.AssertIsBoolean(c.Support[j])
		w := sumVars(api, matchTerms)
		api.AssertIsEqual(api.Mul(w, c.V[j]), api.Sub(c.Support[j], c.Y[j]))
		api.AssertIsEqual(api.Mul(w, c.Y[j]), 0)
	}
	api.AssertIsEqual(c.CY, func() frontend.Variable {
		bitpack := packBits(api, c.Y)
		out, e := poseidonCommit(api, []frontend.Variable{c.DQ, bitpack, c.RhoY}, domainResult)
		if e != nil {
			return 0
		}
		return out
	}())
	return nil
}
