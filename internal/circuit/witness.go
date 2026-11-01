package circuit

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	idenposeidon "github.com/iden3/go-iden3-crypto/v2/poseidon"
	"medproof/internal/poseidon"
	"medproof/internal/workload"
)

func NewIngredientTemplate(s, tu, tm int) (*IngredientCircuit, error) {
	if s < 1 || s > 128 || tu < 1 || tu > 32 || tm < 1 || tm > 32 {
		return nil, errors.New("profile dimensions outside registered limits")
	}
	c := &IngredientCircuit{X: make([]frontend.Variable, tu), R: make([]frontend.Variable, tm), Support: make([]frontend.Variable, tm), A: make([]frontend.Variable, s), B: make([]frontend.Variable, tu), Z: make([]frontend.Variable, tu), M: make([][]frontend.Variable, tm), Y: make([]frontend.Variable, tm), V: make([]frontend.Variable, tm)}
	for j := range c.M {
		c.M[j] = make([]frontend.Variable, tu)
	}
	return c, nil
}

func NewClassTemplate(s, td, q int) (*ClassCircuit, error) {
	if s < 1 || s > 128 || td < 1 || td > 32 || q < 1 || q > 32 {
		return nil, errors.New("class profile dimensions outside registered limits")
	}
	c := &ClassCircuit{A: make([]frontend.Variable, s), Classes: make([][]frontend.Variable, td), C: make([]frontend.Variable, td), Z: make([]frontend.Variable, td)}
	for k := range c.Classes {
		c.Classes[k] = make([]frontend.Variable, q)
	}
	return c, nil
}

func inv(v *big.Int) *big.Int {
	if v.Sign() == 0 {
		return big.NewInt(0)
	}
	z := new(big.Int).ModInverse(v, fr.Modulus())
	if z == nil {
		panic("missing field inverse")
	}
	return z
}
func fieldProduct(vals []*big.Int) *big.Int {
	p := big.NewInt(1)
	for _, v := range vals {
		p.Mul(p, v)
		p.Mod(p, fr.Modulus())
	}
	return p
}
func codeInt(v uint16) *big.Int { return new(big.Int).SetUint64(uint64(v)) }

func BuildIngredientWitness(aCodes []uint16, products []workload.Product, s, tu, tm int, dq *big.Int, rhoA, rhoY *big.Int) (*IngredientCircuit, error) {
	if len(products) == 0 || len(products) > tm || dq == nil || rhoA == nil || rhoY == nil {
		return nil, errors.New("invalid ingredient witness arguments")
	}
	aCommit, paddedA, err := poseidonCommitmentA(aCodes, s, rhoA)
	if err != nil {
		return nil, err
	}
	cols := map[uint16]bool{}
	sets := make([][]uint16, len(products))
	for j, p := range products {
		if !p.Supported {
			continue
		}
		if len(p.Ingredients) == 0 {
			return nil, fmt.Errorf("supported product %d has no resolved ingredients", j)
		}
		ids := append([]uint16(nil), p.Ingredients...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for i, v := range ids {
			if v == 0 || v == 65535 || (i > 0 && ids[i-1] == v) {
				return nil, errors.New("invalid product ingredient set")
			}
			cols[v] = true
		}
		sets[j] = ids
	}
	if len(cols) == 0 || len(cols) > tu {
		return nil, errors.New("empty/over-capacity supported ingredient union")
	}
	xcodes := make([]uint16, 0, len(cols))
	for v := range cols {
		xcodes = append(xcodes, v)
	}
	sort.Slice(xcodes, func(i, j int) bool { return xcodes[i] < xcodes[j] })
	colIndex := map[uint16]int{}
	for i, v := range xcodes {
		colIndex[v] = i
	}
	c, _ := NewIngredientTemplate(s, tu, tm)
	c.CA = aCommit
	c.DQ = dq
	c.RhoA = rhoA
	c.RhoY = rhoY
	for i, v := range paddedA {
		c.A[i] = int(v)
	}
	for i := 0; i < tu; i++ {
		v := uint16(PublicPad)
		if i < len(xcodes) {
			v = xcodes[i]
		}
		c.X[i] = int(v)
		factors := make([]*big.Int, len(paddedA))
		for r, a := range paddedA {
			factors[r] = new(big.Int).Sub(codeInt(v), codeInt(a))
		}
		f := fieldProduct(factors)
		if f.Sign() == 0 {
			c.B[i] = 0
			c.Z[i] = 0
		} else {
			c.B[i] = 1
			c.Z[i] = inv(f)
		}
	}
	alerts := map[uint16]bool{}
	for _, v := range paddedA {
		if v != 0 {
			alerts[v] = true
		}
	}
	flags := make([]bool, tm)
	for j := 0; j < tm; j++ {
		for i := 0; i < tu; i++ {
			c.M[j][i] = 0
		}
		if j >= len(products) || !products[j].Supported {
			c.Support[j] = 0
			c.R[j] = 0
			c.Y[j] = 0
			c.V[j] = 0
			continue
		}
		c.Support[j] = 1
		rowmask := new(big.Int)
		matched := 0
		for _, id := range sets[j] {
			col := colIndex[id]
			c.M[j][col] = 1
			rowmask.SetBit(rowmask, col, 1)
			if alerts[id] {
				matched++
			}
		}
		c.R[j] = rowmask
		flags[j] = matched == 0
		if flags[j] {
			c.Y[j] = 1
			c.V[j] = 0
		} else {
			c.Y[j] = 0
			c.V[j] = inv(big.NewInt(int64(matched)))
		}
	}
	cy, err := poseidon.CommitResult(dq, flags, rhoY)
	if err != nil {
		return nil, err
	}
	c.CY = cy
	return c, nil
}

func poseidonCommitmentA(codes []uint16, s int, rho *big.Int) (*big.Int, []uint16, error) {
	if s < 1 || s > 128 {
		return nil, nil, errors.New("unsupported alert capacity")
	}
	set := append([]uint16(nil), codes...)
	sort.Slice(set, func(i, j int) bool { return set[i] < set[j] })
	uniq := set[:0]
	for _, v := range set {
		if v == 0 || v == 65535 {
			return nil, nil, errors.New("reserved alert code")
		}
		if len(uniq) == 0 || uniq[len(uniq)-1] != v {
			uniq = append(uniq, v)
		}
	}
	if len(uniq) > s {
		return nil, nil, errors.New("alert set exceeds S")
	}
	padded := make([]uint16, s)
	copy(padded, uniq)
	input := make([]*big.Int, 0, (s+14)/15+1)
	for base := 0; base < s; base += 15 {
		w := new(big.Int)
		for j := 0; j < 15 && base+j < s; j++ {
			w.Add(w, new(big.Int).Lsh(codeInt(padded[base+j]), uint(16*j)))
		}
		input = append(input, w)
	}
	input = append(input, new(big.Int).Set(rho))
	out, e := idenposeidon.HashWithState(input, domainAlert)
	return out, padded, e
}

func BuildClassWitness(aCodes []uint16, products []workload.Product, s, td, q int, dq, rhoA, rhoY *big.Int) (*ClassCircuit, []int, error) {
	if len(products) == 0 || dq == nil || rhoA == nil || rhoY == nil {
		return nil, nil, errors.New("invalid class witness arguments")
	}
	ca, paddedA, err := poseidonCommitmentA(aCodes, s, rhoA)
	if err != nil {
		return nil, nil, err
	}
	classIndex := map[string]int{}
	sets := make([][]uint16, 0)
	classOf := make([]int, len(products))
	supportCount := 0
	maxq := 0
	for j, p := range products {
		classOf[j] = -1
		if !p.Supported {
			continue
		}
		if len(p.Ingredients) == 0 {
			return nil, nil, errors.New("supported product has empty ingredient set")
		}
		ids := append([]uint16(nil), p.Ingredients...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for i, v := range ids {
			if v == 0 || v == 65535 || (i > 0 && ids[i-1] == v) {
				return nil, nil, errors.New("invalid class ingredient set")
			}
		}
		if len(ids) > maxq {
			maxq = len(ids)
		}
		key := fmt.Sprint(ids)
		k, ok := classIndex[key]
		if !ok {
			k = len(sets)
			classIndex[key] = k
			sets = append(sets, ids)
		}
		classOf[j] = k
		supportCount++
	}
	if supportCount == 0 || len(sets) > td || maxq > q {
		return nil, nil, errors.New("no supported products or class tier overflow")
	}
	c := &ClassCircuit{CA: ca, DQ: dq, Classes: make([][]frontend.Variable, td), A: make([]frontend.Variable, s), RhoA: rhoA, C: make([]frontend.Variable, td), Z: make([]frontend.Variable, td), RhoY: rhoY}
	for i, v := range paddedA {
		c.A[i] = int(v)
	}
	classFlags := make([]bool, td)
	for k := 0; k < td; k++ {
		c.Classes[k] = make([]frontend.Variable, q)
		real := k < len(sets)
		ids := []uint16{}
		if real {
			ids = sets[k]
		}
		all := make([]*big.Int, 0, q*s)
		for slot := 0; slot < q; slot++ {
			x := uint16(PublicPad)
			if slot < len(ids) {
				x = ids[slot]
			}
			c.Classes[k][slot] = int(x)
			for _, a := range paddedA {
				all = append(all, new(big.Int).Sub(codeInt(x), codeInt(a)))
			}
		}
		tprod := fieldProduct(all)
		flag := tprod.Sign() != 0
		classFlags[k] = flag // padded classes are constrained to one and included in C_Y
		if flag {
			c.C[k] = 1
			c.Z[k] = inv(tprod)
		} else {
			c.C[k] = 0
			c.Z[k] = 0
		}
	}
	cy, err := poseidon.CommitResult(dq, classFlags, rhoY)
	if err != nil {
		return nil, nil, err
	}
	c.CY = cy
	return c, classOf, nil
}

// BuildSparseClassWitness creates one circuit row per supported product and
// gives each row exactly its own ingredient count, with no q-wide padding.
func BuildSparseClassWitness(aCodes []uint16, products []workload.Product, s int, dq, rhoA, rhoY *big.Int) (*ClassCircuit, error) {
	if len(products) == 0 || dq == nil || rhoA == nil || rhoY == nil {
		return nil, errors.New("invalid sparse witness arguments")
	}
	ca, paddedA, err := poseidonCommitmentA(aCodes, s, rhoA)
	if err != nil {
		return nil, err
	}
	c := &ClassCircuit{CA: ca, DQ: dq, A: make([]frontend.Variable, s), RhoA: rhoA, Classes: make([][]frontend.Variable, len(products)), C: make([]frontend.Variable, len(products)), Z: make([]frontend.Variable, len(products)), RhoY: rhoY}
	for i, v := range paddedA {
		c.A[i] = int(v)
	}
	flags := make([]bool, len(products))
	for k, p := range products {
		if !p.Supported || len(p.Ingredients) == 0 {
			return nil, fmt.Errorf("sparse baseline requires supported nonempty product %d", k)
		}
		ids := append([]uint16(nil), p.Ingredients...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		factors := make([]*big.Int, 0, len(ids)*s)
		for i, id := range ids {
			if id == 0 || id == PublicPad || (i > 0 && ids[i-1] == id) {
				return nil, errors.New("invalid sparse product ingredient set")
			}
			c.Classes[k] = append(c.Classes[k], int(id))
			for _, a := range paddedA {
				factors = append(factors, new(big.Int).Sub(codeInt(id), codeInt(a)))
			}
		}
		prod := fieldProduct(factors)
		flags[k] = prod.Sign() != 0
		if flags[k] {
			c.C[k] = 1
			c.Z[k] = inv(prod)
		} else {
			c.C[k] = 0
			c.Z[k] = 0
		}
	}
	cy, err := poseidon.CommitResult(dq, flags, rhoY)
	if err != nil {
		return nil, err
	}
	c.CY = cy
	return c, nil
}

// BuildPackedUncompressedWitness emits a fixed-width product row and result bit
// for every product, retaining duplicate sets and public-sentinel padding.
func BuildPackedUncompressedWitness(aCodes []uint16, products []workload.Product, s, q int, dq, rhoA, rhoY *big.Int) (*ClassCircuit, error) {
	if len(products) == 0 || q < 1 || dq == nil || rhoA == nil || rhoY == nil {
		return nil, errors.New("invalid packed witness arguments")
	}
	ca, paddedA, err := poseidonCommitmentA(aCodes, s, rhoA)
	if err != nil {
		return nil, err
	}
	c := &ClassCircuit{CA: ca, DQ: dq, A: make([]frontend.Variable, s), RhoA: rhoA, Classes: make([][]frontend.Variable, len(products)), C: make([]frontend.Variable, len(products)), Z: make([]frontend.Variable, len(products)), RhoY: rhoY}
	for i, v := range paddedA {
		c.A[i] = int(v)
	}
	flags := make([]bool, len(products))
	for k, p := range products {
		if !p.Supported || len(p.Ingredients) == 0 || len(p.Ingredients) > q {
			return nil, fmt.Errorf("packed product %d invalid or exceeds q", k)
		}
		ids := append([]uint16(nil), p.Ingredients...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		factors := make([]*big.Int, 0, q*s)
		for slot := 0; slot < q; slot++ {
			x := uint16(PublicPad)
			if slot < len(ids) {
				x = ids[slot]
				if slot > 0 && ids[slot-1] == x {
					return nil, errors.New("duplicate product ingredient")
				}
			}
			c.Classes[k] = append(c.Classes[k], int(x))
			for _, a := range paddedA {
				factors = append(factors, new(big.Int).Sub(codeInt(x), codeInt(a)))
			}
		}
		prod := fieldProduct(factors)
		flags[k] = prod.Sign() != 0
		if flags[k] {
			c.C[k] = 1
			c.Z[k] = inv(prod)
		} else {
			c.C[k] = 0
			c.Z[k] = 0
		}
	}
	cy, err := poseidon.CommitResult(dq, flags, rhoY)
	if err != nil {
		return nil, err
	}
	c.CY = cy
	return c, nil
}
