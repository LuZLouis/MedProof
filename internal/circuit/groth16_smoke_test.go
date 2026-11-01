package circuit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	idenposeidon "github.com/iden3/go-iden3-crypto/v2/poseidon"
)

const (
	smokeS  = 16
	smokeN  = 2
	smokeQ  = 2
	smokeTD = 4
)

func fieldInv(v *big.Int) *big.Int {
	if v.Sign() == 0 {
		return big.NewInt(0)
	}
	out := new(big.Int).ModInverse(v, fr.Modulus())
	if out == nil {
		panic("field inverse missing")
	}
	return out
}

func nativeHash(in []*big.Int, domain *big.Int) *big.Int {
	out, err := idenposeidon.HashWithState(in, domain)
	if err != nil {
		panic(err)
	}
	return out
}

func nativeAlertCommit(a []int64, rho int64) *big.Int {
	packed := make([]*big.Int, 0, (len(a)+PackWidth-1)/PackWidth+1)
	for i := 0; i < len(a); i += PackWidth {
		var word big.Int
		for j := 0; j < PackWidth && i+j < len(a); j++ {
			term := new(big.Int).Lsh(big.NewInt(a[i+j]), uint(CodeWidth*j))
			word.Add(&word, term)
		}
		packed = append(packed, new(big.Int).Set(&word))
	}
	packed = append(packed, big.NewInt(rho))
	return nativeHash(packed, domainAlert)
}

func nativeResultCommit(dq int64, bits []int64, rho int64) *big.Int {
	var packed big.Int
	for i, bit := range bits {
		if bit != 0 {
			packed.SetBit(&packed, i, 1)
		}
	}
	return nativeHash([]*big.Int{big.NewInt(dq), &packed, big.NewInt(rho)}, domainResult)
}

func ingredientAssignment() *IngredientCircuit {
	a := make([]frontend.Variable, smokeS)
	a[0] = 7
	for i := 1; i < len(a); i++ {
		a[i] = 0
	}
	x := []frontend.Variable{7, 8}
	m := [][]frontend.Variable{{1, 0}, {0, 1}}
	ca := nativeAlertCommit([]int64{7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 11)
	cy := nativeResultCommit(123, []int64{0, 1}, 12)
	z := make([]frontend.Variable, 2)
	b := make([]frontend.Variable, 2)
	for i, xv := range []int64{7, 8} {
		f := new(big.Int).SetInt64(1)
		for _, av := range []int64{7} {
			f.Mul(f, new(big.Int).Sub(big.NewInt(xv), big.NewInt(av)))
		}
		for r := 1; r < smokeS; r++ {
			f.Mul(f, big.NewInt(xv))
		}
		f.Mod(f, fr.Modulus())
		if f.Sign() == 0 {
			b[i], z[i] = 0, 0
		} else {
			b[i], z[i] = 1, fieldInv(f)
		}
	}
	return &IngredientCircuit{
		CA: ca, CY: cy, DQ: 123, X: x, R: []frontend.Variable{1, 2}, Support: []frontend.Variable{1, 1},
		A: a, RhoA: 11, B: b, Z: z, M: m, Y: []frontend.Variable{0, 1}, V: []frontend.Variable{1, 0}, RhoY: 12,
	}
}

func classAssignment() *ClassCircuit {
	classes := [][]frontend.Variable{{7, PublicPad}, {8, PublicPad}, {PublicPad, PublicPad}, {PublicPad, PublicPad}}
	a := make([]frontend.Variable, smokeS)
	a[0] = 7
	for i := 1; i < len(a); i++ {
		a[i] = 0
	}
	ca := nativeAlertCommit([]int64{7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 11)
	cy := nativeResultCommit(123, []int64{0, 1, 1, 1}, 12)
	z := make([]frontend.Variable, smokeTD)
	sets := [][]int64{{7, int64(PublicPad)}, {8, int64(PublicPad)}, {int64(PublicPad), int64(PublicPad)}, {int64(PublicPad), int64(PublicPad)}}
	for k, set := range sets {
		f := big.NewInt(1)
		for _, x := range set {
			for r := 0; r < smokeS; r++ {
				av := int64(0)
				if r == 0 {
					av = 7
				}
				f.Mul(f, new(big.Int).Sub(big.NewInt(x), big.NewInt(av)))
			}
		}
		f.Mod(f, fr.Modulus())
		if f.Sign() == 0 {
			z[k] = 0
		} else {
			z[k] = fieldInv(f)
		}
	}
	return &ClassCircuit{CA: ca, CY: cy, DQ: 123, Classes: classes, A: a, RhoA: 11, C: []frontend.Variable{0, 1, 1, 1}, Z: z, RhoY: 12}
}

func runGroth16Smoke(t *testing.T, circuit, assignment frontend.Circuit) {
	t.Helper()
	start := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	compileTime := time.Since(start)
	start = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	setupTime := time.Since(start)
	start = time.Now()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proveTimeWitness := time.Since(start)
	start = time.Now()
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	proveTime := time.Since(start)
	start = time.Now()
	public, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, public); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	verifyTime := time.Since(start)
	t.Logf("smoke constraints=%d compile_ms=%d setup_ms=%d witness_ms=%d prove_ms=%d verify_ms=%d", ccs.GetNbConstraints(), compileTime.Milliseconds(), setupTime.Milliseconds(), proveTimeWitness.Milliseconds(), proveTime.Milliseconds(), verifyTime.Milliseconds())
	writeSmokeRecord(t, assignment, ccs.GetNbConstraints(), compileTime, setupTime, proveTimeWitness, proveTime, verifyTime, proof, public, pk, vk)

	// A changed public statement must not verify against the same proof.
	var tampered frontend.Circuit
	switch a := assignment.(type) {
	case *IngredientCircuit:
		bad := *a
		bad.DQ = 124
		tampered = &bad
	case *ClassCircuit:
		bad := *a
		bad.DQ = 124
		tampered = &bad
	}
	badWitness, err := frontend.NewWitness(tampered, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	badPublic, err := badWitness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, badPublic); err == nil {
		t.Fatal("tampered request digest unexpectedly verified")
	}
	var badAssignment frontend.Circuit
	switch a := assignment.(type) {
	case *IngredientCircuit:
		bad := *a
		bad.Y = append([]frontend.Variable(nil), a.Y...)
		bad.Y[0] = 1 // inconsistent with the committed output and hidden match bits
		badAssignment = &bad
	case *ClassCircuit:
		bad := *a
		bad.C = append([]frontend.Variable(nil), a.C...)
		bad.C[0] = 1 // inconsistent with the committed class result
		badAssignment = &bad
	}
	invalidWitness, err := frontend.NewWitness(badAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = groth16.Prove(ccs, pk, invalidWitness); err == nil {
		t.Fatal("invalid private result witness unexpectedly proved")
	}
	_ = proveTimeWitness
}

type smokeRecord struct {
	RunID              string   `json:"run_id"`
	Commit             *string  `json:"commit"`
	Seed               int      `json:"seed"`
	WorkloadSource     string   `json:"workload_source"`
	Backend            string   `json:"backend"`
	Curve              string   `json:"curve"`
	Variant            string   `json:"variant"`
	Mode               string   `json:"mode"`
	S                  int      `json:"S"`
	M                  int      `json:"m"`
	MSupported         int      `json:"m_supported"`
	U                  *int     `json:"u"`
	L                  *int     `json:"L"`
	H                  *int     `json:"h"`
	Q                  *int     `json:"q"`
	TU                 *int     `json:"t_u"`
	TM                 *int     `json:"t_m"`
	TD                 *int     `json:"t_d"`
	Alpha              *float64 `json:"alpha"`
	ProfileHash        string   `json:"profile_hash"`
	RequestedMode      string   `json:"requested_mode"`
	SelectedMode       string   `json:"selected_mode"`
	R1CSConstraints    int      `json:"r1cs_constraints"`
	NonlinearEstimate  int      `json:"nonlinear_estimate"`
	WitnessMS          int64    `json:"witness_ms"`
	ProveMS            int64    `json:"prove_ms"`
	VerifyMS           int64    `json:"verify_ms"`
	SetupMS            int64    `json:"setup_ms"`
	CompileMS          int64    `json:"compile_ms"`
	PeakRSSMB          *float64 `json:"peak_rss_mb"`
	ProofBytes         int64    `json:"proof_bytes"`
	PublicInputBytes   int64    `json:"public_input_bytes"`
	PKBytes            int64    `json:"pk_bytes"`
	VKBytes            int64    `json:"vk_bytes"`
	RequestDigest      *string  `json:"request_digest"`
	FixturePublicHash  string   `json:"fixture_public_hash"`
	Status             string   `json:"status"`
	Threads            int      `json:"threads"`
	GoVersion          string   `json:"go_version"`
	GnarkVersion       string   `json:"gnark_version"`
	GnarkCryptoVersion string   `json:"gnark_crypto_version"`
	CPUInfo            string   `json:"cpu_info"`
}

func serializedSize(t *testing.T, obj io.WriterTo) int64 {
	t.Helper()
	var b bytes.Buffer
	n, err := obj.WriteTo(&b)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func writeSmokeRecord(t *testing.T, assignment frontend.Circuit, constraints int, compile, setup, witness, prove, verify time.Duration, proof groth16.Proof, public io.WriterTo, pk groth16.ProvingKey, vk groth16.VerifyingKey) {
	t.Helper()
	mode, variant := "", ""
	var u, l, h, q, tu, tm, td *int
	nonlinear := 0
	switch assignment.(type) {
	case *IngredientCircuit:
		mode, variant = "ingredient", "MedProof-V13-ingredient-smoke"
		u, l, tu, tm = intRef(2), intRef(2), intRef(smokeN), intRef(smokeN)
		nonlinear = smokeN*(smokeS+1) + smokeN*(2*smokeN+2)
	case *ClassCircuit:
		mode, variant = "class", "MedProof-V13-class-smoke"
		u, l, h, q, td = intRef(2), intRef(2), intRef(2), intRef(smokeQ), intRef(smokeTD)
		nonlinear = smokeTD * (smokeS*smokeQ + 1)
	}
	profile := sha256.Sum256([]byte(variant + "/S=16/n=2/iden3-poseidon-v2.0.0"))
	fixture := sha256.Sum256([]byte("synthetic-public-shape-v1/seed=7/S=16/m=2"))
	r := smokeRecord{
		RunID: time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + mode,
		Seed:  7, WorkloadSource: "synthetic-fixture-v1", Backend: "Groth16", Curve: "BN254", Variant: variant,
		Mode: mode, S: smokeS, M: 2, MSupported: 2, U: u, L: l, H: h, Q: q, TU: tu, TM: tm, TD: td,
		ProfileHash: hex.EncodeToString(profile[:]), RequestedMode: mode, SelectedMode: mode, R1CSConstraints: constraints,
		NonlinearEstimate: nonlinear, WitnessMS: witness.Milliseconds(), ProveMS: prove.Milliseconds(), VerifyMS: verify.Milliseconds(),
		SetupMS: setup.Milliseconds(), CompileMS: compile.Milliseconds(), ProofBytes: serializedSize(t, proof),
		PublicInputBytes: serializedSize(t, public), PKBytes: serializedSize(t, pk), VKBytes: serializedSize(t, vk),
		FixturePublicHash: hex.EncodeToString(fixture[:]), Status: "smoke_prove_verify_pass;protocol_not_complete",
		Threads: runtime.GOMAXPROCS(0), GoVersion: runtime.Version(), GnarkVersion: "v0.16.4",
		GnarkCryptoVersion: "v0.21.1-0.20260913224755-1409fe592052", CPUInfo: "12th Gen Intel Core i7-12700; 12 cores/20 logical CPUs",
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join("..", "..", "results", "smoke"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "results", "smoke", mode+".json")
	if err = os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func intRef(x int) *int { return &x }

func TestGroth16IngredientBranchSmoke(t *testing.T) {
	a := ingredientAssignment()
	template := &IngredientCircuit{X: make([]frontend.Variable, smokeN), R: make([]frontend.Variable, smokeN), Support: make([]frontend.Variable, smokeN), A: make([]frontend.Variable, smokeS), B: make([]frontend.Variable, smokeN), Z: make([]frontend.Variable, smokeN), M: make([][]frontend.Variable, smokeN), Y: make([]frontend.Variable, smokeN), V: make([]frontend.Variable, smokeN)}
	for i := range template.M {
		template.M[i] = make([]frontend.Variable, smokeN)
	}
	runGroth16Smoke(t, template, a)
}

func TestGroth16ClassBranchSmoke(t *testing.T) {
	a := classAssignment()
	template := &ClassCircuit{Classes: make([][]frontend.Variable, smokeTD), A: make([]frontend.Variable, smokeS), C: make([]frontend.Variable, smokeTD), Z: make([]frontend.Variable, smokeTD)}
	for i := range template.Classes {
		template.Classes[i] = make([]frontend.Variable, smokeQ)
	}
	runGroth16Smoke(t, template, a)
}
