package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"medproof/internal/workload"
)

func TestWitnessBuildersForBothBranches(t *testing.T) {
	products := []workload.Product{
		{Name: "synthetic-1", Ingredients: []uint16{7, 8}, Supported: true},
		{Name: "synthetic-2", Ingredients: []uint16{9}, Supported: true},
		{Name: "synthetic-3", Supported: false},
	}
	dq := big.NewInt(123)
	rhoA := big.NewInt(11)
	rhoY := big.NewInt(12)
	ing, err := BuildIngredientWitness([]uint16{8}, products, 16, 4, 4, dq, rhoA, rhoY)
	if err != nil {
		t.Fatal(err)
	}
	ingTemplate, err := NewIngredientTemplate(16, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(ingTemplate, ing, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("ingredient witness failed: %v", err)
	}
	if ing.Y[0] != 0 || ing.Y[1] != 1 || ing.Y[2] != 0 {
		t.Fatalf("unexpected hidden flags: %v", ing.Y)
	}
	cls, classOf, err := BuildClassWitness([]uint16{8}, products, 16, 4, 2, dq, rhoA, rhoY)
	if err != nil {
		t.Fatal(err)
	}
	clsTemplate, err := NewClassTemplate(16, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(clsTemplate, cls, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("class witness failed: %v", err)
	}
	if len(classOf) != 3 || classOf[0] != 0 || classOf[1] != 1 || classOf[2] != -1 {
		t.Fatalf("bad class map: %v", classOf)
	}
}
