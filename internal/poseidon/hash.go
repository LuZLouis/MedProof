// Package poseidon implements the BN254 Poseidon permutation parameters used
// by iden3/go-iden3-crypto v2.0.0 (Circom-compatible parameter tables).
// Constants are vendored from that Apache-2.0/MIT dual-licensed release.
package poseidon

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/iden3/go-iden3-crypto/v2/ff"
	idenposeidon "github.com/iden3/go-iden3-crypto/v2/poseidon"
)

// Native computes the upstream Poseidon hash with the provided initial state.
func Native(inputs []*big.Int, initState *big.Int) (*big.Int, error) {
	return idenposeidon.HashWithState(inputs, initState)
}

func constant(v interface{ ToBigIntRegular(*big.Int) *big.Int }) *big.Int {
	var out big.Int
	v.ToBigIntRegular(&out)
	return &out
}

const NROUNDSF = 8

var NROUNDSP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}

func addAll(api frontend.API, terms []frontend.Variable) frontend.Variable {
	if len(terms) == 1 {
		return terms[0]
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

func addRound(api frontend.API, state []frontend.Variable, round []*ffElement, start int) {
	for i := range state {
		state[i] = api.Add(state[i], constant(round[start+i]))
	}
}

// ffElement is a narrow alias used only to keep the constant access local.
type ffElement = ff.Element

func sbox(api frontend.API, x frontend.Variable) frontend.Variable {
	x2 := api.Mul(x, x)
	x4 := api.Mul(x2, x2)
	return api.Mul(x4, x)
}

func mix(api frontend.API, state []frontend.Variable, matrix [][]*ffElement) []frontend.Variable {
	out := make([]frontend.Variable, len(state))
	for i := range out {
		terms := make([]frontend.Variable, len(state))
		for j := range state {
			terms[j] = api.Mul(constant(matrix[j][i]), state[j])
		}
		out[i] = addAll(api, terms)
	}
	return out
}

// CircuitHash computes exactly iden3 Poseidon HashWithState for a fixed input
// arity. The arity must be 1..16 and must be the same in native and circuit use.
func CircuitHash(api frontend.API, inputs []frontend.Variable, initState frontend.Variable) (frontend.Variable, error) {
	if len(inputs) < 1 || len(inputs) > 16 {
		return nil, fmt.Errorf("Poseidon input arity %d outside [1,16]", len(inputs))
	}
	t := len(inputs) + 1
	idx := t - 2
	C, S, M, P := c.c[idx], c.s[idx], c.m[idx], c.p[idx]
	state := make([]frontend.Variable, t)
	if initial, ok := initState.(*big.Int); ok {
		state[0] = new(big.Int).Set(initial)
	} else {
		state[0] = initState
	}
	copy(state[1:], inputs)
	addRound(api, state, C, 0)
	for i := 0; i < NROUNDSF/2-1; i++ {
		for j := range state {
			state[j] = sbox(api, state[j])
		}
		addRound(api, state, C, (i+1)*t)
		state = mix(api, state, M)
	}
	for j := range state {
		state[j] = sbox(api, state[j])
	}
	addRound(api, state, C, (NROUNDSF/2)*t)
	state = mix(api, state, P)
	for i := 0; i < NROUNDSP[idx]; i++ {
		state[0] = sbox(api, state[0])
		state[0] = api.Add(state[0], constant(C[(NROUNDSF/2+1)*t+i]))
		new0Terms := make([]frontend.Variable, t)
		for j := 0; j < t; j++ {
			new0Terms[j] = api.Mul(constant(S[(t*2-1)*i+j]), state[j])
		}
		new0 := addAll(api, new0Terms)
		for k := 1; k < t; k++ {
			state[k] = api.Add(state[k], api.Mul(state[0], constant(S[(t*2-1)*i+t+k-1])))
		}
		state[0] = new0
	}
	for i := 0; i < NROUNDSF/2-1; i++ {
		for j := range state {
			state[j] = sbox(api, state[j])
		}
		addRound(api, state, C, (NROUNDSF/2+1)*t+NROUNDSP[idx]+i*t)
		state = mix(api, state, M)
	}
	for j := range state {
		state[j] = sbox(api, state[j])
	}
	state = mix(api, state, M)
	return state[0], nil
}
