package poseidon

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sort"
)

var scalarModulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

func AlertDomain() *big.Int  { return new(big.Int).SetBytes([]byte("MedProof/commit/A")) }
func ResultDomain() *big.Int { return new(big.Int).SetBytes([]byte("MedProof/commit/Y")) }

func RandomOpening() (*big.Int, error) { return rand.Int(rand.Reader, scalarModulus) }

// CommitAlert normalizes an already capacity-checked code set and commits to
// 15-code little-endian packed words followed by a fresh scalar opening.
func CommitAlert(codes []uint16, capacity int, rho *big.Int) (*big.Int, []uint16, error) {
	if capacity < 1 || len(codes) > capacity || rho == nil || rho.Sign() < 0 || rho.Cmp(scalarModulus) >= 0 {
		return nil, nil, errors.New("invalid alert commitment inputs")
	}
	set := append([]uint16(nil), codes...)
	sort.Slice(set, func(i, j int) bool { return set[i] < set[j] })
	out := set[:0]
	for _, code := range set {
		if code == 0 || code == 65535 {
			return nil, nil, errors.New("alert code outside [1,65534]")
		}
		if len(out) == 0 || out[len(out)-1] != code {
			out = append(out, code)
		}
	}
	if len(out) > capacity {
		return nil, nil, errors.New("unique alerts exceed capacity")
	}
	padded := make([]uint16, capacity)
	copy(padded, out)
	inputs := make([]*big.Int, 0, (capacity+14)/15+1)
	for base := 0; base < capacity; base += 15 {
		var word big.Int
		for j := 0; j < 15 && base+j < capacity; j++ {
			word.Add(&word, new(big.Int).Lsh(big.NewInt(int64(padded[base+j])), uint(16*j)))
		}
		inputs = append(inputs, new(big.Int).Set(&word))
	}
	inputs = append(inputs, new(big.Int).Set(rho))
	commitment, err := Native(inputs, AlertDomain())
	return commitment, padded, err
}

func CommitResult(requestDigest *big.Int, results []bool, rho *big.Int) (*big.Int, error) {
	if requestDigest == nil || requestDigest.Sign() < 0 || requestDigest.Cmp(scalarModulus) >= 0 || rho == nil || rho.Sign() < 0 || rho.Cmp(scalarModulus) >= 0 || len(results) == 0 || len(results) > 32 {
		return nil, errors.New("invalid result commitment inputs")
	}
	var bits big.Int
	for i, value := range results {
		if value {
			bits.SetBit(&bits, i, 1)
		}
	}
	return Native([]*big.Int{new(big.Int).Set(requestDigest), new(big.Int).Set(&bits), new(big.Int).Set(rho)}, ResultDomain())
}
