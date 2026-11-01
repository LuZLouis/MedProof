package workload

import (
	"errors"
	"fmt"
	"math/rand"
	"sort"
)

// GenerateHeterogeneous constructs a fixed, deterministic sparse-baseline
// workload with product ingredient counts 1,2,3,4 (each class repeated twice).
func GenerateHeterogeneous(seed int64) Batch {
	sets := [][]uint16{{1}, {2, 3}, {4, 5, 6}, {5, 6, 7, 8}}
	products := make([]Product, 0, 8)
	for class, ids := range sets {
		for repeat := 0; repeat < 2; repeat++ {
			products = append(products, Product{Name: fmt.Sprintf("synthetic-mixed-%02d", len(products)+1), Ingredients: append([]uint16(nil), ids...), Supported: true, Class: class})
		}
	}
	return Batch{Seed: seed, Source: "legal-synthetic-heterogeneous-fixture", Products: products, U: 8, L: 20, H: 4, Q: 4, Alpha: 0.6}
}

type Product struct {
	Name          string   `json:"name"`
	TerminologyID string   `json:"terminology_id,omitempty"`
	Ingredients   []uint16 `json:"ingredients,omitempty"`
	Supported     bool     `json:"supported"`
	Class         int      `json:"class,omitempty"`
}

type Batch struct {
	Seed               int64     `json:"seed"`
	Source             string    `json:"source"`
	Products           []Product `json:"products"`
	U                  int       `json:"u"`
	L                  int       `json:"L"`
	H                  int       `json:"h"`
	Q                  int       `json:"q"`
	Alpha              float64   `json:"alpha"`
	TerminologyRelease string    `json:"terminology_release,omitempty"`
	Normalization      string    `json:"normalization,omitempty"`
	MappingDigest      string    `json:"mapping_digest,omitempty"`
	// Benchmark-only metadata is deliberately excluded from fixture hashes.
	Rep        int    `json:"-"`
	WorkloadID string `json:"-"`
	RunOrder   int    `json:"-"`
}

// Generate constructs a feasible synthetic structure with exactly m products,
// u distinct ingredients, h complete ingredient-set classes and q ingredients
// per supported product. It never purports to model clinical prevalence.
func Generate(seed int64, m, u, h, q int) (Batch, error) {
	if m < 1 || m > 32 || u < 1 || u > 32 || h < 1 || q < 1 || h > m || q > u || u > q*h {
		return Batch{}, errors.New("infeasible dimensions: require m,h,q,u>0; h<=m; q<=u; u<=q*h")
	}
	maxClasses := combinations(u, q, h)
	if maxClasses < h {
		return Batch{}, fmt.Errorf("infeasible: only %d distinct q-subsets exist for requested h=%d", maxClasses, h)
	}
	rng := rand.New(rand.NewSource(seed))
	var sets [][]uint16
	for attempt := 0; attempt < 10000; attempt++ {
		sets = make([][]uint16, h)
		perm := rng.Perm(u)
		// Place every ingredient into a distinct class slot first. This makes
		// full-union coverage constructive instead of a low-probability event.
		for idx, ingredient := range perm {
			sets[idx/q] = append(sets[idx/q], uint16(ingredient+1))
		}
		for class := range sets {
			for len(sets[class]) < q {
				candidate := uint16(rng.Intn(u) + 1)
				present := false
				for _, existing := range sets[class] {
					if existing == candidate {
						present = true
						break
					}
				}
				if !present {
					sets[class] = append(sets[class], candidate)
				}
			}
			sort.Slice(sets[class], func(i, j int) bool { return sets[class][i] < sets[class][j] })
		}
		seen := map[string]bool{}
		unique := true
		for _, set := range sets {
			key := fmt.Sprint(set)
			if seen[key] {
				unique = false
				break
			}
			seen[key] = true
		}
		if unique {
			break
		}
		sets = nil
	}
	if len(sets) != h {
		return Batch{}, errors.New("could not construct requested ingredient union with this seed")
	}
	products := make([]Product, m)
	for j := range products {
		class := j % h
		products[j] = Product{Name: fmt.Sprintf("synthetic-product-%02d", j+1), Ingredients: append([]uint16(nil), sets[class]...), Supported: true, Class: class}
	}
	rng.Shuffle(len(products), func(i, j int) { products[i], products[j] = products[j], products[i] })
	alpha := 1 - float64(u)/float64(m*q)
	return Batch{Seed: seed, Source: "legal-synthetic-fixture", Products: products, U: u, L: m * q, H: h, Q: q, Alpha: alpha}, nil
}

func combinations(n, k, stopAt int) int {
	if k > n-k {
		k = n - k
	}
	v := 1
	for i := 1; i <= k; i++ {
		v = v * (n - k + i) / i
		if v >= stopAt {
			return stopAt
		}
	}
	return v
}
