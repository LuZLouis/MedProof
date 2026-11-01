package workload

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

const RxNormWorkloadEnv = "MEDPROOF_RXNORM_WORKLOADS"

type frozenRxNormWorkloads struct {
	Batches []Batch `json:"batches"`
}

var rxNormCache sync.Map // path -> map[batchKey]Batch

type batchKey struct {
	seed       int64
	m, u, h, q int
}

func loadRxNormWorkloads(path string) (map[batchKey]Batch, error) {
	if cached, ok := rxNormCache.Load(path); ok {
		return cached.(map[batchKey]Batch), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read frozen RxNorm workload file: %w", err)
	}
	var data frozenRxNormWorkloads
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("decode frozen RxNorm workload file: %w", err)
	}
	if len(data.Batches) == 0 {
		return nil, fmt.Errorf("frozen RxNorm workload file has no batches")
	}
	byKey := make(map[batchKey]Batch, len(data.Batches))
	for _, b := range data.Batches {
		if b.Source != "rxnorm-prescribable-20261005" || len(b.Products) == 0 {
			if b.Source == "rxnorm-prescribable-20261005-heterogeneous" {
				continue
			}
			return nil, fmt.Errorf("unexpected RxNorm workload source %q", b.Source)
		}
		k := batchKey{seed: b.Seed, m: len(b.Products), u: b.U, h: b.H, q: b.Q}
		if _, exists := byKey[k]; exists {
			return nil, fmt.Errorf("duplicate frozen RxNorm workload key %+v", k)
		}
		if err := validateRxNormBatch(b); err != nil {
			return nil, err
		}
		byKey[k] = b
	}
	actual, _ := rxNormCache.LoadOrStore(path, byKey)
	return actual.(map[batchKey]Batch), nil
}

func validateRxNormBatch(b Batch) error {
	seenProduct := map[string]bool{}
	union := map[uint16]bool{}
	length := 0
	for _, p := range b.Products {
		if p.TerminologyID == "" || !p.Supported || len(p.Ingredients) == 0 {
			return fmt.Errorf("invalid RxNorm product in seed %d", b.Seed)
		}
		if seenProduct[p.TerminologyID] {
			return fmt.Errorf("duplicate RxCUI %s in seed %d", p.TerminologyID, b.Seed)
		}
		seenProduct[p.TerminologyID] = true
		length += len(p.Ingredients)
		for _, code := range p.Ingredients {
			if code == 0 {
				return fmt.Errorf("zero ingredient code in RxNorm seed %d", b.Seed)
			}
			union[code] = true
		}
	}
	if len(union) != b.U || length != b.L || len(b.Products) == 0 {
		return fmt.Errorf("RxNorm seed %d workload dimensions do not match its products", b.Seed)
	}
	return nil
}

// GenerateFromSource returns a frozen RxNorm-derived workload when the runner
// is started with MEDPROOF_RXNORM_WORKLOADS; otherwise it retains synthetic mode.
func GenerateFromSource(seed int64, m, u, h, q int) (Batch, error) {
	path := os.Getenv(RxNormWorkloadEnv)
	if path == "" {
		return Generate(seed, m, u, h, q)
	}
	byKey, err := loadRxNormWorkloads(path)
	if err != nil {
		return Batch{}, err
	}
	b, ok := byKey[batchKey{seed: seed, m: m, u: u, h: h, q: q}]
	if !ok {
		return Batch{}, fmt.Errorf("no frozen RxNorm batch for seed=%d,m=%d,u=%d,h=%d,q=%d", seed, m, u, h, q)
	}
	return b, nil
}

// GenerateHeterogeneousFromSource selects the frozen variable-width RxNorm batch
// in RxNorm mode, and the existing deterministic fixture otherwise.
func GenerateHeterogeneousFromSource(seed int64) (Batch, error) {
	path := os.Getenv(RxNormWorkloadEnv)
	if path == "" {
		return GenerateHeterogeneous(seed), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Batch{}, fmt.Errorf("read frozen RxNorm workload file: %w", err)
	}
	var data frozenRxNormWorkloads
	if err := json.Unmarshal(b, &data); err != nil {
		return Batch{}, fmt.Errorf("decode frozen RxNorm workload file: %w", err)
	}
	for _, batch := range data.Batches {
		if batch.Seed == seed && batch.Source == "rxnorm-prescribable-20261005-heterogeneous" {
			if err := validateRxNormBatch(batch); err != nil {
				return Batch{}, err
			}
			return batch, nil
		}
	}
	return Batch{}, fmt.Errorf("no frozen heterogeneous RxNorm batch for seed %d", seed)
}
