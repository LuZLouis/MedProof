package workload

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFrozenRxNormWorkloadsAreReproducibleAndMapped(t *testing.T) {
	path := filepath.Join("..", "..", "data", "public_sources", "rxnorm_prescribable_20261005_workloads.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("optional RxNorm workload data is not distributed with the source repository")
	}
	t.Setenv(RxNormWorkloadEnv, path)
	a, err := GenerateFromSource(11, 8, 8, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateFromSource(11, 8, 8, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if a.Source != "rxnorm-prescribable-20261005" || a.MappingDigest == "" || a.TerminologyRelease == "" {
		t.Fatalf("missing RxNorm provenance: %+v", a)
	}
	if len(a.Products) != 8 || a.U != 8 || a.L != 16 || a.H != 4 || a.Q != 2 {
		t.Fatalf("unexpected frozen workload dimensions: %+v", a)
	}
	for i := range a.Products {
		if a.Products[i].TerminologyID == "" || a.Products[i].TerminologyID != b.Products[i].TerminologyID || len(a.Products[i].Ingredients) != 2 {
			t.Fatalf("unexpected or non-deterministic product at index %d: %+v / %+v", i, a.Products[i], b.Products[i])
		}
	}
	if a.Alpha != b.Alpha || a.Products[0].Name != b.Products[0].Name {
		t.Fatal("same seed did not return the same frozen RxNorm workload")
	}
}

func TestFrozenRxNormHeterogeneousBatchUsesRealConcepts(t *testing.T) {
	path := filepath.Join("..", "..", "data", "public_sources", "rxnorm_prescribable_20261005_workloads.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("optional RxNorm workload data is not distributed with the source repository")
	}
	t.Setenv(RxNormWorkloadEnv, path)
	b, err := GenerateHeterogeneousFromSource(11)
	if err != nil {
		t.Fatal(err)
	}
	if b.Source != "rxnorm-prescribable-20261005-heterogeneous" || len(b.Products) != 8 || b.Q != 4 {
		t.Fatalf("unexpected heterogeneous batch: %+v", b)
	}
	widths := map[int]bool{}
	for _, p := range b.Products {
		if p.TerminologyID == "" {
			t.Fatal("heterogeneous workload contains a product without an RxCUI")
		}
		widths[len(p.Ingredients)] = true
	}
	for _, width := range []int{1, 2, 3, 4} {
		if !widths[width] {
			t.Fatalf("missing ingredient width %d in heterogeneous batch", width)
		}
	}
}
