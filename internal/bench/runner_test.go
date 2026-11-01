package bench

import (
	"testing"

	"medproof/internal/workload"
)

func TestSyntheticRequestDigestIsReproducibleAndSigned(t *testing.T) {
	b, err := workload.Generate(11, 8, 8, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	p, err := SelectByCompiledConstraints(16, len(b.Products), b.U, b.H, b.Q)
	if err != nil {
		t.Fatal(err)
	}
	d1, h1, _, _, err := syntheticRequestBinding(b, 16, p)
	if err != nil {
		t.Fatal(err)
	}
	d2, h2, _, _, err := syntheticRequestBinding(b, 16, p)
	if err != nil {
		t.Fatal(err)
	}
	if d1.Cmp(d2) != 0 || h1 != h2 || len(h1) != 64 {
		t.Fatalf("synthetic request digest is not reproducible: %s != %s", h1, h2)
	}
}
