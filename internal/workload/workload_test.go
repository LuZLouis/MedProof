package workload

import (
	"fmt"
	"testing"
)

func TestGenerateFeasibleAndDeterministic(t *testing.T) {
	a, err := Generate(17, 8, 8, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(17, 8, 8, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if a.U != 8 || a.L != 16 || a.H != 4 || a.Q != 2 || len(a.Products) != 8 {
		t.Fatalf("wrong dimensions: %+v", a)
	}
	seen := map[uint16]bool{}
	classes := map[string]bool{}
	for _, p := range a.Products {
		if !p.Supported || len(p.Ingredients) != 2 {
			t.Fatal("synthetic product invalid")
		}
		seen[p.Ingredients[0]] = true
		seen[p.Ingredients[1]] = true
		classes[fmt.Sprint(p.Ingredients)] = true
	}
	if len(seen) != 8 || len(classes) != 4 {
		t.Fatalf("expected 8 ingredients/4 classes, got %d/%d", len(seen), len(classes))
	}
	if fmt.Sprint(a.Products) != fmt.Sprint(b.Products) {
		t.Fatal("seeded generator is not deterministic")
	}
}

func TestGenerateConstructivelyCoversLargerUnions(t *testing.T) {
	for _, tc := range []struct {
		seed       int64
		m, u, h, q int
	}{
		{11, 16, 16, 8, 2},
		{23, 32, 32, 8, 4},
		{37, 8, 16, 8, 4},
	} {
		b, err := Generate(tc.seed, tc.m, tc.u, tc.h, tc.q)
		if err != nil {
			t.Fatalf("Generate(%d,%d,%d,%d,%d): %v", tc.seed, tc.m, tc.u, tc.h, tc.q, err)
		}
		union, classes := map[uint16]bool{}, map[string]bool{}
		for _, p := range b.Products {
			if len(p.Ingredients) != tc.q {
				t.Fatalf("seed %d product width %d, want %d", tc.seed, len(p.Ingredients), tc.q)
			}
			classes[fmt.Sprint(p.Ingredients)] = true
			for _, id := range p.Ingredients {
				union[id] = true
			}
		}
		if len(union) != tc.u || len(classes) != tc.h {
			t.Fatalf("seed %d got union/classes %d/%d, want %d/%d", tc.seed, len(union), len(classes), tc.u, tc.h)
		}
	}
}

func TestParseMedicationNamesRestrictedPythonList(t *testing.T) {
	got, err := parseMedicationNames("['ロキソプロフェン', '薬\\'A']")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "ロキソプロフェン" || got[1] != "薬'A" {
		t.Fatalf("unexpected parsed names: %#v", got)
	}
	if empty, err := parseMedicationNames("[]"); err != nil || len(empty) != 0 {
		t.Fatalf("empty list: %#v, %v", empty, err)
	}
	if _, err := parseMedicationNames("__import__('os')"); err == nil {
		t.Fatal("non-list expression accepted")
	}
}

func TestGeneratorRejectsInfeasibleDimensions(t *testing.T) {
	if _, err := Generate(1, 4, 8, 1, 2); err == nil {
		t.Fatal("u>q*h accepted")
	}
	if _, err := Generate(1, 4, 3, 2, 3); err == nil {
		t.Fatal("h>number of unique sets accepted")
	}
}

func TestFixtureResolverNormalizationAndUnsupported(t *testing.T) {
	r, err := NewFixtureResolver(map[string][]uint16{"  Rx-A ": {3, 1}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r.Resolve("rx-a")
	if !ok || len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("bad normalized lookup %v %v", got, ok)
	}
	if _, ok := r.Resolve("unknown"); ok {
		t.Fatal("unknown product resolved")
	}
}
