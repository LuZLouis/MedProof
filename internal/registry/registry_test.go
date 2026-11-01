package registry

import "testing"

func TestProfileHashAndCircuitTemplates(t *testing.T) {
	a := Profile{Mode: "ingredient", S: 16, TU: 4, TM: 4}
	b := Profile{Mode: "class", S: 16, TD: 4, Q: 2}
	ha, err := HashProfile(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := HashProfile(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Fatal("different proof profiles share a hash")
	}
	if _, err := Compile(a); err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(b); err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(Profile{Mode: "ingredient", S: 16, TU: 0, TM: 4}); err == nil {
		t.Fatal("invalid tier compiled")
	}
}
