package bench

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"medproof/internal/circuit"
	"medproof/internal/poseidon"
	"medproof/internal/protocol"
	"medproof/internal/registry"
	"medproof/internal/workload"
)

// Record keeps measured quantities and fixture provenance for one proof.
type Record struct {
	RunID            string         `json:"run_id"`
	Rep              int            `json:"rep,omitempty"`
	WorkloadID       string         `json:"workload_id,omitempty"`
	RunOrder         int            `json:"run_order,omitempty"`
	CalibFlag        int            `json:"calib_flag,omitempty"`
	CompileNS        int64          `json:"compile_ns,omitempty"`
	SetupNS          *int64         `json:"setup_ns,omitempty"`
	WitnessNS        int64          `json:"witness_ns,omitempty"`
	ProveNS          int64          `json:"prove_ns,omitempty"`
	VerifyNS         int64          `json:"verify_ns,omitempty"`
	ReceiptSignNS    int64          `json:"receipt_sign_ns,omitempty"`
	ReceiptVerifyNS  int64          `json:"receipt_verify_ns,omitempty"`
	PeakRSSMiB       *float64       `json:"peak_rss_mib,omitempty"`
	TimingLoopK      map[string]int `json:"timing_loop_k,omitempty"`
	Commit           *string        `json:"commit"`
	ManifestSHA256   string         `json:"manifest_sha256"`
	WorkloadSHA256   string         `json:"workload_sha256"`
	RequestDigest    *string        `json:"request_digest"`
	RequestBuildNS   int64          `json:"request_build_ns"`
	RequestSignNS    int64          `json:"request_sign_verify_ns"`
	SelectorMS       *int64         `json:"selector_compile_ms"`
	Seed             int64          `json:"seed"`
	WorkloadSource   string         `json:"workload_source"`
	Backend          string         `json:"backend"`
	Curve            string         `json:"curve"`
	Variant          string         `json:"variant"`
	Mode             string         `json:"mode"`
	S                int            `json:"S"`
	M                int            `json:"m"`
	MSupported       int            `json:"m_supported"`
	U                int            `json:"u"`
	L                int            `json:"L"`
	H                int            `json:"h"`
	Q                int            `json:"q"`
	TU               int            `json:"t_u,omitempty"`
	TM               int            `json:"t_m,omitempty"`
	TD               int            `json:"t_d,omitempty"`
	Alpha            float64        `json:"alpha"`
	ProfileHash      string         `json:"profile_hash"`
	RequestedMode    string         `json:"requested_mode"`
	SelectedMode     string         `json:"selected_mode"`
	Constraints      int            `json:"r1cs_constraints"`
	CompileMS        int64          `json:"compile_ms"`
	SetupMS          *int64         `json:"setup_ms"`
	WitnessMS        int64          `json:"witness_ms"`
	ProveMS          int64          `json:"prove_ms"`
	VerifyMS         int64          `json:"verify_ms"`
	ProofBytes       int            `json:"proof_bytes"`
	PublicInputBytes int            `json:"public_input_bytes"`
	PKBytes          int            `json:"pk_bytes"`
	VKBytes          int            `json:"vk_bytes"`
	PeakRSSMB        *float64       `json:"peak_rss_mb"`
	Status           string         `json:"status"`
}

func setV2Metadata(r *Record, b workload.Batch) {
	r.Rep = b.Rep
	r.WorkloadID = b.WorkloadID
	r.RunOrder = b.RunOrder
	if b.Rep > 0 {
		r.PeakRSSMiB = r.PeakRSSMB
		r.TimingLoopK = map[string]int{"request_build": 100, "request_sign_verify": 100, "witness": 100, "verify": 20, "receipt_sign_verify": 1000}
	}
}

func receiptTiming(batch workload.Batch, digest string, assignment frontend.Circuit) (int64, int64, error) {
	var cy frontend.Variable
	switch a := assignment.(type) {
	case *circuit.IngredientCircuit:
		cy = a.CY
	case *circuit.ClassCircuit:
		cy = a.CY
	default:
		return 0, 0, fmt.Errorf("unsupported assignment for receipt: %T", assignment)
	}
	cyText := fmt.Sprint(cy)
	seedKey := sha256.Sum256([]byte(fmt.Sprintf("MedProof/recipient-test-key/v1\x00%d", batch.Seed)))
	privateKey := ed25519.NewKeyFromSeed(seedKey[:])
	const k = 1000
	unsigned := protocol.ReceiptUnsigned{RequestID: fmt.Sprintf("session-%d-%s", batch.Seed, digest[:12]), Digest: digest, CY: cyText, Status: "received"}
	start := time.Now()
	var receipt protocol.Receipt
	for i := 0; i < k; i++ {
		var err error
		receipt, err = protocol.SignReceipt(unsigned, "synthetic-recipient", privateKey)
		if err != nil {
			return time.Since(start).Nanoseconds() / k, 0, err
		}
	}
	signNS := time.Since(start).Nanoseconds() / k
	start = time.Now()
	for i := 0; i < k; i++ {
		if !protocol.VerifyReceipt(receipt, privateKey.Public().(ed25519.PublicKey)) {
			return signNS, time.Since(start).Nanoseconds() / k, fmt.Errorf("receipt signature failed verification")
		}
	}
	verifyNS := time.Since(start).Nanoseconds() / k
	return signNS, verifyNS, nil
}

func newWitnessForRun(assignment frontend.Circuit, batch workload.Batch) (witness.Witness, int64, error) {
	if batch.Rep > 0 {
		const k = 100
		start := time.Now()
		var w witness.Witness
		for i := 0; i < k; i++ {
			var err error
			w, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				return nil, 0, err
			}
		}
		return w, time.Since(start).Nanoseconds() / k, nil
	}
	start := time.Now()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	return w, time.Since(start).Nanoseconds(), err
}

func verifyForRun(proof groth16.Proof, vk groth16.VerifyingKey, pub witness.Witness, batch workload.Batch) (int64, error) {
	if batch.Rep > 0 {
		const k = 20
		start := time.Now()
		for i := 0; i < k; i++ {
			if err := groth16.Verify(proof, vk, pub); err != nil {
				return 0, err
			}
		}
		return time.Since(start).Nanoseconds() / k, nil
	}
	start := time.Now()
	err := groth16.Verify(proof, vk, pub)
	return time.Since(start).Nanoseconds(), err
}

func maxRSS(a, b *float64) *float64 {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if *a > *b {
		return a
	}
	return b
}

func productDigest(batchDigest *big.Int, index int) *big.Int {
	h := sha256.Sum256([]byte(fmt.Sprintf("MedProof/independent-request/v1\x00%x\x00%d", batchDigest, index)))
	v := new(big.Int).SetBytes(h[:])
	return v.Mod(v, ecc.BN254.ScalarField())
}

type dispatchKey struct{ s, m, u, h, q int }

var dispatchCacheMu sync.Mutex
var dispatchCache = map[dispatchKey]registry.Profile{}

func cachedDispatch(s, m, u, h, q int) (registry.Profile, int64, error) {
	k := dispatchKey{s, m, u, h, q}
	dispatchCacheMu.Lock()
	if p, ok := dispatchCache[k]; ok {
		dispatchCacheMu.Unlock()
		return p, 0, nil
	}
	dispatchCacheMu.Unlock()
	start := time.Now()
	p, err := SelectByCompiledConstraints(s, m, u, h, q)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return registry.Profile{}, elapsed, err
	}
	dispatchCacheMu.Lock()
	dispatchCache[k] = p
	dispatchCacheMu.Unlock()
	return p, elapsed, nil
}

// syntheticRequestBinding makes a canonical, signed request over the exact
// ordered synthetic candidate array and returns the digest used by C_Y.
// The key is deterministic test material and must never be used in production.
func syntheticRequestBinding(batch workload.Batch, s int, selected registry.Profile) (*big.Int, string, int64, int64, error) {
	start := time.Now()
	request, digest, err := buildSyntheticRequest(batch, s, selected)
	buildNS := time.Since(start).Nanoseconds()
	if err != nil {
		return nil, "", buildNS, 0, err
	}
	seedKey := sha256.Sum256([]byte(fmt.Sprintf("MedProof/synthetic-coordinator-test-key/v1\x00%d", batch.Seed)))
	privateKey := ed25519.NewKeyFromSeed(seedKey[:])
	start = time.Now()
	signed, err := protocol.SignRequest(request, "synthetic-coordinator", privateKey)
	if err != nil {
		return nil, "", buildNS, time.Since(start).Nanoseconds(), err
	}
	if !protocol.VerifyRequestSignature(signed, privateKey.Public().(ed25519.PublicKey)) {
		return nil, "", buildNS, time.Since(start).Nanoseconds(), fmt.Errorf("synthetic request signature failed verification")
	}
	return digest, fmt.Sprintf("%064x", digest), buildNS, time.Since(start).Nanoseconds(), nil
}

func syntheticRequestBindingMeasured(batch workload.Batch, s int, selected registry.Profile) (*big.Int, string, int64, int64, error) {
	const k = 100
	start := time.Now()
	var request protocol.Request
	var digest *big.Int
	for i := 0; i < k; i++ {
		var err error
		request, digest, err = buildSyntheticRequest(batch, s, selected)
		if err != nil {
			return nil, "", 0, 0, err
		}
	}
	buildNS := time.Since(start).Nanoseconds() / k
	seedKey := sha256.Sum256([]byte(fmt.Sprintf("MedProof/synthetic-coordinator-test-key/v1\x00%d", batch.Seed)))
	privateKey := ed25519.NewKeyFromSeed(seedKey[:])
	start = time.Now()
	for i := 0; i < k; i++ {
		signed, err := protocol.SignRequest(request, "synthetic-coordinator", privateKey)
		if err != nil {
			return nil, "", buildNS, 0, err
		}
		if !protocol.VerifyRequestSignature(signed, privateKey.Public().(ed25519.PublicKey)) {
			return nil, "", buildNS, 0, fmt.Errorf("synthetic request signature failed verification")
		}
	}
	signNS := time.Since(start).Nanoseconds() / k
	return digest, fmt.Sprintf("%064x", digest), buildNS, signNS, nil
}

func requestBindingForRun(batch workload.Batch, s int, selected registry.Profile) (*big.Int, string, int64, int64, error) {
	if batch.Rep > 0 {
		return syntheticRequestBindingMeasured(batch, s, selected)
	}
	return syntheticRequestBinding(batch, s, selected)
}

func buildSyntheticRequest(batch workload.Batch, s int, selected registry.Profile) (protocol.Request, *big.Int, error) {
	ca, _, err := poseidon.CommitAlert([]uint16{1, 3, 5}, s, big.NewInt(batch.Seed+20000))
	if err != nil {
		return protocol.Request{}, nil, err
	}
	capture := protocol.Capture{SchemaVersion: "candidate-array-v1", Candidates: make([]protocol.Candidate, 0, len(batch.Products))}
	for _, p := range batch.Products {
		if p.Supported {
			conceptID := p.TerminologyID
			if conceptID == "" {
				conceptID = p.Name
			}
			capture.Candidates = append(capture.Candidates, protocol.Candidate{Kind: "concept", ConceptID: conceptID})
		} else {
			capture.Candidates = append(capture.Candidates, protocol.Candidate{Kind: "unresolved_text", Text: p.Name})
		}
	}
	raw, err := json.Marshal(capture)
	if err != nil {
		return protocol.Request{}, nil, err
	}
	release, normalization, mappingDigest := batch.TerminologyRelease, batch.Normalization, batch.MappingDigest
	if release == "" {
		release, normalization, mappingDigest = "synthetic-fixture-v1", "fixture-normalization-v1", workloadDigest(batch)
	}
	nu := protocol.TerminologyProfile{Release: release, Normalization: normalization, MappingDigest: mappingDigest}
	tier := protocol.Tier{Mode: selected.Mode, S: selected.S, TU: selected.TU, TM: selected.TM, TD: selected.TD, Q: selected.Q}
	fixtureDigest := workloadDigest(batch)
	request, err := protocol.NewRequest(fmt.Sprintf("session-%d-%s", batch.Seed, fixtureDigest[:12]), ca.String(), "synthetic-snapshot-v1", "synthetic-parser-v1", fmt.Sprintf("nonce-%d-%s", batch.Seed, fixtureDigest[:12]), "auto", nu, tier, raw)
	if err != nil {
		return protocol.Request{}, nil, err
	}
	digest, err := protocol.RequestDigest(request)
	if err != nil {
		return protocol.Request{}, nil, err
	}
	return request, digest, nil
}

func manifestDigestForOutput(output string) string {
	name := "configs/e2_manifest.json"
	if strings.Contains(strings.ToLower(filepath.Base(output)), "e1_") {
		name = "configs/e1_manifest.json"
	}
	h, e := ManifestHash(name)
	if e != nil {
		return ""
	}
	return h
}
func workloadDigest(batch workload.Batch) string {
	b, e := json.Marshal(batch)
	if e != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func addProvenance(r *Record, b workload.Batch, output string) {
	r.ManifestSHA256 = manifestDigestForOutput(output)
	r.WorkloadSHA256 = workloadDigest(b)
}

// EnrichRunFile adds manifest and deterministic fixture hashes to the measured
// records after re-deriving each fixture from its frozen seed and dimensions.
func EnrichRunFile(path, manifest string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	var records []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4<<20)
	for sc.Scan() {
		var r Record
		if e = json.Unmarshal(sc.Bytes(), &r); e != nil {
			return e
		}
		records = append(records, r)
	}
	if e = sc.Err(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	for i := range records {
		r := &records[i]
		var b workload.Batch
		if strings.Contains(r.WorkloadSource, "heterogeneous") {
			b, e = workload.GenerateHeterogeneousFromSource(r.Seed)
		} else {
			b, e = workload.GenerateFromSource(r.Seed, r.M, r.U, r.H, r.Q)
		}
		if e != nil {
			return e
		}
		r.M = len(b.Products)
		r.MSupported = len(b.Products)
		r.U = b.U
		r.L = b.L
		r.H = b.H
		r.Q = b.Q
		r.Alpha = b.Alpha
		addProvenance(r, b, path)
		if manifest != "" {
			r.ManifestSHA256, _ = ManifestHash(manifest)
		}
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	for _, r := range records {
		if e = enc.Encode(r); e != nil {
			return e
		}
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, out.Bytes(), 0644); e != nil {
		return e
	}
	backup := path + ".enrich-backup"
	_ = os.Remove(backup)
	if e = os.Rename(path, backup); e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		_ = os.Rename(backup, path)
		return e
	}
	return os.Remove(backup)
}

// RunProfile performs one actual compile/Setup and seeded Prove/Verify runs.
func RunProfile(p registry.Profile, seeds []int64, output string, variant string) error {
	return RunProfileShape(p, seeds, output, variant, 0, 0, 0, 0)
}

// RunProfileShape measures an explicitly specified legal synthetic workload.
func RunProfileShape(p registry.Profile, seeds []int64, output string, variant string, m, u, h, q int) error {
	if len(seeds) == 0 {
		return fmt.Errorf("empty seed list")
	}
	batches := make([]workload.Batch, 0, len(seeds))
	for _, seed := range seeds {
		var b workload.Batch
		var e error
		if m > 0 {
			b, e = workload.GenerateFromSource(seed, m, u, h, q)
		} else {
			b, e = profileWorkload(p, seed)
		}
		if e != nil {
			return e
		}
		batches = append(batches, b)
	}
	return RunProfileBatches(p, batches, output, variant)
}

// RunProfileShapeRepeated runs fixed seeds repeatedly while compiling and
// setting up the profile once. The first fixture is used for an unrecorded warmup.
func RunProfileShapeRepeated(p registry.Profile, seeds []int64, output, variant string, m, u, h, q, reps, runOrder int, workloadID string) error {
	if reps < 1 || len(seeds) == 0 {
		return fmt.Errorf("invalid repeated workload dimensions")
	}
	batches := make([]workload.Batch, 0, len(seeds)*reps)
	for _, seed := range seeds {
		for rep := 1; rep <= reps; rep++ {
			var b workload.Batch
			var err error
			if m > 0 {
				b, err = workload.GenerateFromSource(seed, m, u, h, q)
			} else {
				b, err = profileWorkload(p, seed)
			}
			if err != nil {
				return err
			}
			b.Rep, b.WorkloadID, b.RunOrder = rep, workloadID, runOrder
			batches = append(batches, b)
		}
	}
	return RunProfileBatches(p, batches, output, variant)
}

func RepeatBatches(source []workload.Batch, reps, runOrder int, workloadID string) ([]workload.Batch, error) {
	if len(source) == 0 || reps < 1 {
		return nil, fmt.Errorf("invalid repeated batch dimensions")
	}
	out := make([]workload.Batch, 0, len(source)*reps)
	for _, b := range source {
		for rep := 1; rep <= reps; rep++ {
			b.Rep, b.WorkloadID, b.RunOrder = rep, workloadID, runOrder
			out = append(out, b)
		}
	}
	return out, nil
}

// RunProfileBatches measures the same exact ordered fixtures across proof variants.
func RunProfileBatches(p registry.Profile, batches []workload.Batch, output string, variant string) error {
	if len(batches) == 0 {
		return fmt.Errorf("empty workload batches")
	}
	first := batches[0]
	selected, selectorMS, err := cachedDispatch(p.S, len(first.Products), first.U, first.H, first.Q)
	if err != nil {
		return err
	}
	runtime.GC()
	debug.FreeOSMemory()
	stopSetupRSS := startPeakRSSSampling()
	template, err := registry.Compile(p)
	if err != nil {
		return err
	}
	compileStart := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, template)
	if err != nil {
		return err
	}
	compileElapsed := time.Since(compileStart)
	compileMS := compileElapsed.Milliseconds()
	setupStart := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}
	setupElapsed := time.Since(setupStart)
	setupMS := setupElapsed.Milliseconds()
	setupRSS := stopSetupRSS()
	ph, err := registry.HashProfile(p)
	if err != nil {
		return err
	}
	var pkb, vkb bytes.Buffer
	_, _ = pk.WriteTo(&pkb)
	_, _ = vk.WriteTo(&vkb)
	if err = os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if first.Rep > 0 {
		if err := warmupProfile(p, first, selected, ccs, pk, vk); err != nil {
			return fmt.Errorf("warmup failed: %w", err)
		}
	}
	for n, batch := range batches {
		stopSeedRSS := startPeakRSSSampling()
		seed := batch.Seed
		dq, digestText, requestBuildMS, requestSignMS, err := requestBindingForRun(batch, p.S, selected)
		if err != nil {
			return err
		}
		rhoA := big.NewInt(seed + 20000)
		rhoY := big.NewInt(seed + 30000)
		var assignment frontend.Circuit
		if p.Mode == "ingredient" {
			assignment, err = circuit.BuildIngredientWitness([]uint16{1, 3, 5}, batch.Products, p.S, p.TU, p.TM, dq, rhoA, rhoY)
		} else {
			assignment, _, err = circuit.BuildClassWitness([]uint16{1, 3, 5}, batch.Products, p.S, p.TD, p.Q, dq, rhoA, rhoY)
		}
		if err != nil {
			return err
		}
		witness, witnessNS, err := newWitnessForRun(assignment, batch)
		witnessElapsed := time.Duration(witnessNS)
		witnessMS := witnessElapsed.Milliseconds()
		if err != nil {
			return err
		}
		ps := time.Now()
		proof, err := groth16.Prove(ccs, pk, witness)
		proveElapsed := time.Since(ps)
		proveMS := proveElapsed.Milliseconds()
		if err != nil {
			return err
		}
		pub, err := witness.Public()
		if err != nil {
			return err
		}
		verifyNS, verr := verifyForRun(proof, vk, pub, batch)
		verifyElapsed := time.Duration(verifyNS)
		err = verr
		verifyMS := verifyElapsed.Milliseconds()
		if err != nil {
			return err
		}
		seedRSS := stopSeedRSS()
		peakRSS := maxRSS(setupRSS, seedRSS)
		var proofBuf, pubBuf bytes.Buffer
		_, _ = proof.WriteTo(&proofBuf)
		_, _ = pub.WriteTo(&pubBuf)
		receiptSignNS, receiptVerifyNS := int64(0), int64(0)
		if batch.Rep > 0 {
			receiptSignNS, receiptVerifyNS, err = receiptTiming(batch, digestText, assignment)
			if err != nil {
				return err
			}
		}
		r := Record{RunID: time.Now().UTC().Format("20060102T150405.000000000Z"), Seed: seed, WorkloadSource: batch.Source, Backend: "Groth16", Curve: "BN254", Variant: variant, Mode: p.Mode, S: p.S, M: len(batch.Products), MSupported: len(batch.Products), U: batch.U, L: batch.L, H: batch.H, Q: batch.Q, Alpha: batch.Alpha, ProfileHash: ph, RequestedMode: "auto", SelectedMode: selected.Mode, Constraints: ccs.GetNbConstraints(), CompileMS: compileMS, CompileNS: compileElapsed.Nanoseconds(), RequestDigest: &digestText, RequestBuildNS: requestBuildMS, RequestSignNS: requestSignMS, WitnessMS: witnessMS, WitnessNS: witnessElapsed.Nanoseconds(), ProveMS: proveMS, ProveNS: proveElapsed.Nanoseconds(), VerifyMS: verifyMS, VerifyNS: verifyElapsed.Nanoseconds(), ReceiptSignNS: receiptSignNS, ReceiptVerifyNS: receiptVerifyNS, ProofBytes: proofBuf.Len(), PublicInputBytes: pubBuf.Len(), PKBytes: pkb.Len(), VKBytes: vkb.Len(), PeakRSSMB: peakRSS, SetupNS: int64Ptr(setupElapsed.Nanoseconds()), Status: "prove_verify_pass"}
		setV2Metadata(&r, batch)
		addProvenance(&r, batch, output)
		if p.Mode == "ingredient" {
			r.TU = p.TU
			r.TM = p.TM
		} else {
			r.TD = p.TD
		}
		if n == 0 {
			r.SetupMS = &setupMS
			if selectorMS > 0 {
				r.SelectorMS = &selectorMS
			}
		}
		if err = enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

func int64Ptr(v int64) *int64 { return &v }

func warmupProfile(p registry.Profile, batch workload.Batch, selected registry.Profile, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	dq, _, _, _, err := syntheticRequestBinding(batch, p.S, selected)
	if err != nil {
		return err
	}
	rhoA, rhoY := big.NewInt(batch.Seed+20000), big.NewInt(batch.Seed+30000)
	var assignment frontend.Circuit
	if p.Mode == "ingredient" {
		assignment, err = circuit.BuildIngredientWitness([]uint16{1, 3, 5}, batch.Products, p.S, p.TU, p.TM, dq, rhoA, rhoY)
	} else {
		assignment, _, err = circuit.BuildClassWitness([]uint16{1, 3, 5}, batch.Products, p.S, p.TD, p.Q, dq, rhoA, rhoY)
	}
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return err
	}
	pub, err := w.Public()
	if err != nil {
		return err
	}
	return groth16.Verify(proof, vk, pub)
}

type CalibrationRunner struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
	p   registry.Profile
	b   workload.Batch
}

func NewCalibrationRunner() (*CalibrationRunner, error) {
	p := registry.Profile{Mode: "ingredient", S: 16, TU: 8, TM: 8}
	b, err := workload.GenerateFromSource(11, 8, 8, 4, 2)
	if err != nil {
		return nil, err
	}
	t, err := registry.Compile(p)
	if err != nil {
		return nil, err
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, t)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &CalibrationRunner{ccs: ccs, pk: pk, vk: vk, p: p, b: b}, nil
}

func (c *CalibrationRunner) Run(path string, runOrder int) ([]int64, error) {
	dq, _, _, _, err := syntheticRequestBinding(c.b, c.p.S, c.p)
	if err != nil {
		return nil, err
	}
	a, err := circuit.BuildIngredientWitness([]uint16{1, 3, 5}, c.b.Products, c.p.S, c.p.TU, c.p.TM, dq, big.NewInt(c.b.Seed+20000), big.NewInt(c.b.Seed+30000))
	if err != nil {
		return nil, err
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	newFile := false
	if _, err = os.Stat(path); os.IsNotExist(err) {
		newFile = true
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cw := csv.NewWriter(f)
	if newFile {
		if err = cw.Write([]string{"timestamp_utc", "run_order", "trial", "prove_ns"}); err != nil {
			return nil, err
		}
	}
	values := make([]int64, 0, 3)
	for i := 1; i <= 3; i++ {
		start := time.Now()
		proof, e := groth16.Prove(c.ccs, c.pk, w)
		elapsed := time.Since(start).Nanoseconds()
		if e != nil {
			return values, e
		}
		pub, e := w.Public()
		if e != nil {
			return values, e
		}
		if e = groth16.Verify(proof, c.vk, pub); e != nil {
			return values, e
		}
		values = append(values, elapsed)
		if err = cw.Write([]string{time.Now().UTC().Format(time.RFC3339Nano), strconv.Itoa(runOrder), strconv.Itoa(i), strconv.FormatInt(elapsed, 10)}); err != nil {
			return values, err
		}
	}
	cw.Flush()
	if err = cw.Error(); err != nil {
		return values, err
	}
	return values, nil
}

func warmupSparse(batch workload.Batch, selected registry.Profile, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	dq, _, _, _, err := syntheticRequestBinding(batch, 16, selected)
	if err != nil {
		return err
	}
	a, err := circuit.BuildSparseClassWitness([]uint16{1, 3, 5}, batch.Products, 16, dq, big.NewInt(batch.Seed+20000), big.NewInt(batch.Seed+30000))
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return err
	}
	pub, err := w.Public()
	if err != nil {
		return err
	}
	return groth16.Verify(proof, vk, pub)
}

func warmupPacked(batch workload.Batch, selected registry.Profile, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	dq, _, _, _, err := syntheticRequestBinding(batch, 16, selected)
	if err != nil {
		return err
	}
	a, err := circuit.BuildPackedUncompressedWitness([]uint16{1, 3, 5}, batch.Products, 16, batch.Q, dq, big.NewInt(batch.Seed+20000), big.NewInt(batch.Seed+30000))
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return err
	}
	pub, err := w.Public()
	if err != nil {
		return err
	}
	return groth16.Verify(proof, vk, pub)
}

func profileWorkload(p registry.Profile, seed int64) (workload.Batch, error) {
	if p.Mode == "ingredient" {
		m := p.TM
		if m > 8 {
			m = 8
		}
		u := p.TU
		if u > 8 {
			u = 8
		}
		if m < 1 || u < 1 {
			return workload.Batch{}, fmt.Errorf("invalid profile")
		}
		h := m
		if h > u {
			h = u
		}
		q := (u + h - 1) / h
		return workload.Generate(seed, m, u, h, q)
	}
	h := p.TD
	if h > 4 {
		h = 4
	}
	q := p.Q
	if q > 4 {
		q = 4
	}
	if h < 1 || q < 1 {
		return workload.Batch{}, fmt.Errorf("invalid profile")
	}
	m := h * 2
	if m > 8 {
		m = 8
	}
	u := q * h
	if u > 8 {
		u = 8
	}
	if u < q {
		u = q
	}
	return workload.Generate(seed, m, u, h, q)
}

// ManifestHash supplies a stable provenance value for experiment-level records.
func ManifestHash(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// SelectByCompiledConstraints compiles feasible candidate templates and applies
// the protocol tie-break (ingredient before class).
func SelectByCompiledConstraints(s, m, u, h, q int) (registry.Profile, error) {
	candidates := []registry.Profile{{Mode: "ingredient", S: s, TU: roundTier(u), TM: roundTier(m)}, {Mode: "class", S: s, TD: roundTier(h), Q: q}}
	best := -1
	bestN := 0
	for i, p := range candidates {
		t, e := registry.Compile(p)
		if e != nil {
			return registry.Profile{}, e
		}
		c, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, t)
		if e != nil {
			return registry.Profile{}, e
		}
		n := c.GetNbConstraints()
		if best < 0 || n < bestN {
			best, bestN = i, n
		}
	}
	return candidates[best], nil
}

func roundTier(n int) int {
	for _, tier := range []int{4, 8, 16, 32} {
		if n <= tier {
			return tier
		}
	}
	return 0
}

// RunIndependentBatch measures one actual proof per product and aggregates
// proof, public-input, prove, verify, and witness costs for the whole batch.
func RunIndependentBatch(batches []workload.Batch, output string) error {
	if len(batches) == 0 {
		return fmt.Errorf("empty independent baseline workload")
	}
	first := batches[0]
	selected, selectorMS, err := cachedDispatch(16, len(first.Products), first.U, first.H, first.Q)
	if err != nil {
		return err
	}
	runtime.GC()
	debug.FreeOSMemory()
	q := batches[0].Q
	p := registry.Profile{Mode: "class", S: 16, TD: 1, Q: q}
	stopSetupRSS := startPeakRSSSampling()
	template, e := registry.Compile(p)
	if e != nil {
		return e
	}
	cs := time.Now()
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, template)
	if e != nil {
		return e
	}
	compileElapsed := time.Since(cs)
	compileMS := compileElapsed.Milliseconds()
	compileNS := compileElapsed.Nanoseconds()
	ss := time.Now()
	pk, vk, e := groth16.Setup(ccs)
	if e != nil {
		return e
	}
	setupElapsed := time.Since(ss)
	setupMS := setupElapsed.Milliseconds()
	setupNS := setupElapsed.Nanoseconds()
	setupRSS := stopSetupRSS()
	ph, e := registry.HashProfile(p)
	if e != nil {
		return e
	}
	var pkb, vkb bytes.Buffer
	_, _ = pk.WriteTo(&pkb)
	_, _ = vk.WriteTo(&vkb)
	if e = os.MkdirAll(filepath.Dir(output), 0755); e != nil {
		return e
	}
	f, e := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if first.Rep > 0 {
		bd, _, _, _, we := syntheticRequestBinding(first, 16, selected)
		if we != nil {
			return we
		}
		wa, _, we := circuit.BuildClassWitness([]uint16{1, 3, 5}, []workload.Product{first.Products[0]}, 16, 1, q, productDigest(bd, 0), big.NewInt(first.Seed+20000), big.NewInt(first.Seed+30000))
		if we != nil {
			return we
		}
		ww, we := frontend.NewWitness(wa, ecc.BN254.ScalarField())
		if we != nil {
			return we
		}
		wp, we := groth16.Prove(ccs, pk, ww)
		if we != nil {
			return we
		}
		wu, we := ww.Public()
		if we != nil {
			return we
		}
		if we = groth16.Verify(wp, vk, wu); we != nil {
			return we
		}
	}
	for batchIndex, batch := range batches {
		stopBatchRSS := startPeakRSSSampling()
		batchDigest, digestText, requestBuildMS, requestSignMS, err := requestBindingForRun(batch, 16, selected)
		if err != nil {
			return err
		}
		seed := batch.Seed
		m := len(batch.Products)
		u := batch.U
		var totalW, totalP, totalV int64
		var totalWNS, totalPNS, totalVNS, totalReceiptSignNS, totalReceiptVerifyNS int64
		totalProof, totalPublic := 0, 0
		for j, product := range batch.Products {
			assignment, _, e := circuit.BuildClassWitness([]uint16{1, 3, 5}, []workload.Product{product}, 16, 1, q, productDigest(batchDigest, j), big.NewInt(seed+20000), big.NewInt(seed+30000+int64(j)))
			if e != nil {
				return e
			}
			w, witnessNS, e := newWitnessForRun(assignment, batch)
			witnessElapsed := time.Duration(witnessNS)
			totalW += witnessElapsed.Milliseconds()
			totalWNS += witnessElapsed.Nanoseconds()
			if e != nil {
				return e
			}
			ps := time.Now()
			proof, e := groth16.Prove(ccs, pk, w)
			proveElapsed := time.Since(ps)
			totalP += proveElapsed.Milliseconds()
			totalPNS += proveElapsed.Nanoseconds()
			if e != nil {
				return e
			}
			pub, e := w.Public()
			if e != nil {
				return e
			}
			verifyNS, e := verifyForRun(proof, vk, pub, batch)
			verifyElapsed := time.Duration(verifyNS)
			totalV += verifyElapsed.Milliseconds()
			totalVNS += verifyElapsed.Nanoseconds()
			if e != nil {
				return e
			}
			digestText := fmt.Sprintf("%064x", productDigest(batchDigest, j))
			rs, rv, e := receiptTiming(batch, digestText, assignment)
			if e != nil {
				return e
			}
			totalReceiptSignNS += rs
			totalReceiptVerifyNS += rv
			var pb, ub bytes.Buffer
			_, _ = proof.WriteTo(&pb)
			_, _ = pub.WriteTo(&ub)
			totalProof += pb.Len()
			totalPublic += ub.Len()
		}
		batchRSS := stopBatchRSS()
		var setupRecordMS *int64
		if batchIndex == 0 {
			setupRecordMS = &setupMS
		}
		r := Record{RunID: time.Now().UTC().Format("20060102T150405.000000000Z"), Seed: seed, WorkloadSource: batch.Source, Backend: "Groth16", Curve: "BN254", Variant: "independent_zkp", Mode: "class-per-product", S: 16, M: m, MSupported: m, U: u, L: batch.L, H: batch.H, Q: q, TD: 1, Alpha: batch.Alpha, ProfileHash: ph, RequestDigest: &digestText, RequestBuildNS: requestBuildMS, RequestSignNS: requestSignMS, RequestedMode: "auto", SelectedMode: selected.Mode, Constraints: ccs.GetNbConstraints(), CompileMS: compileMS, CompileNS: compileNS, SetupMS: setupRecordMS, SetupNS: int64Ptr(setupNS), WitnessMS: totalW, WitnessNS: totalWNS, ProveMS: totalP, ProveNS: totalPNS, VerifyMS: totalV, VerifyNS: totalVNS, ReceiptSignNS: totalReceiptSignNS, ReceiptVerifyNS: totalReceiptVerifyNS, ProofBytes: totalProof, PublicInputBytes: totalPublic, PKBytes: pkb.Len(), VKBytes: vkb.Len(), PeakRSSMB: maxRSS(setupRSS, batchRSS), Status: "batch_aggregate_of_per_product_proofs"}
		setV2Metadata(&r, batch)
		if batchIndex == 0 {
			if selectorMS > 0 {
				r.SelectorMS = &selectorMS
			}
		}
		addProvenance(&r, batch, output)
		if e = enc.Encode(r); e != nil {
			return e
		}
	}
	return nil
}

// RunSparseBatch sets up a shape-specialized one-row-per-product circuit whose
// public row widths exactly match ingredient counts in the frozen workload.
func RunSparseBatch(batches []workload.Batch, output string) error {
	if len(batches) == 0 {
		return fmt.Errorf("empty sparse workload")
	}
	first := batches[0]
	selected, selectorMS, err := cachedDispatch(16, len(first.Products), first.U, first.H, first.Q)
	if err != nil {
		return err
	}
	runtime.GC()
	debug.FreeOSMemory()
	if len(first.Products) == 0 {
		return fmt.Errorf("empty product list")
	}
	shape := make([]int, len(first.Products))
	tmpl := &circuit.ClassCircuit{A: make([]frontend.Variable, 16), Classes: make([][]frontend.Variable, len(first.Products)), C: make([]frontend.Variable, len(first.Products)), Z: make([]frontend.Variable, len(first.Products))}
	for j, p := range first.Products {
		if !p.Supported || len(p.Ingredients) == 0 {
			return fmt.Errorf("sparse profile requires supported products")
		}
		shape[j] = len(p.Ingredients)
		tmpl.Classes[j] = make([]frontend.Variable, shape[j])
	}
	profileJSON, _ := json.Marshal(struct {
		S      int
		Widths []int
	}{16, shape})
	ph := sha256.Sum256(append([]byte("MedProof/sparse-shape/v1\x00"), profileJSON...))
	stopSetupRSS := startPeakRSSSampling()
	cs := time.Now()
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, tmpl)
	if e != nil {
		return e
	}
	compileElapsed := time.Since(cs)
	compileMS := compileElapsed.Milliseconds()
	ss := time.Now()
	pk, vk, e := groth16.Setup(ccs)
	if e != nil {
		return e
	}
	setupElapsed := time.Since(ss)
	setupMS := setupElapsed.Milliseconds()
	setupRSS := stopSetupRSS()
	var pkb, vkb bytes.Buffer
	_, _ = pk.WriteTo(&pkb)
	_, _ = vk.WriteTo(&vkb)
	if e = os.MkdirAll(filepath.Dir(output), 0755); e != nil {
		return e
	}
	f, e := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if first.Rep > 0 {
		if err := warmupSparse(first, selected, ccs, pk, vk); err != nil {
			return fmt.Errorf("sparse warmup failed: %w", err)
		}
	}
	for n, batch := range batches {
		stopBatchRSS := startPeakRSSSampling()
		dq, digestText, requestBuildMS, requestSignMS, err := requestBindingForRun(batch, 16, selected)
		if err != nil {
			return err
		}
		if len(batch.Products) != len(shape) {
			return fmt.Errorf("sparse batch shape changed")
		}
		for j, p := range batch.Products {
			if len(p.Ingredients) != shape[j] {
				return fmt.Errorf("sparse row width changed at %d", j)
			}
		}
		a, err := circuit.BuildSparseClassWitness([]uint16{1, 3, 5}, batch.Products, 16, dq, big.NewInt(batch.Seed+20000), big.NewInt(batch.Seed+30000))
		if err != nil {
			return err
		}
		w, witnessNS, err := newWitnessForRun(a, batch)
		witnessElapsed := time.Duration(witnessNS)
		witnessMS := witnessElapsed.Milliseconds()
		if err != nil {
			return err
		}
		ps := time.Now()
		proof, err := groth16.Prove(ccs, pk, w)
		proveElapsed := time.Since(ps)
		proveMS := proveElapsed.Milliseconds()
		if err != nil {
			return err
		}
		pub, err := w.Public()
		if err != nil {
			return err
		}
		verifyNS, verr := verifyForRun(proof, vk, pub, batch)
		verifyElapsed := time.Duration(verifyNS)
		err = verr
		verifyMS := verifyElapsed.Milliseconds()
		if err != nil {
			return err
		}
		var pb, ub bytes.Buffer
		_, _ = proof.WriteTo(&pb)
		_, _ = pub.WriteTo(&ub)
		qmax := 0
		for _, v := range shape {
			if v > qmax {
				qmax = v
			}
		}
		batchRSS := stopBatchRSS()
		receiptSignNS, receiptVerifyNS := int64(0), int64(0)
		if batch.Rep > 0 {
			receiptSignNS, receiptVerifyNS, err = receiptTiming(batch, digestText, a)
			if err != nil {
				return err
			}
		}
		r := Record{RunID: time.Now().UTC().Format("20060102T150405.000000000Z"), Seed: batch.Seed, WorkloadSource: batch.Source, Backend: "Groth16", Curve: "BN254", Variant: "sparse_packed_shape_specialized", Mode: "sparse", S: 16, M: len(batch.Products), MSupported: len(batch.Products), U: batch.U, L: batch.L, H: batch.H, Q: qmax, TD: len(shape), ProfileHash: hex.EncodeToString(ph[:]), RequestDigest: &digestText, RequestBuildNS: requestBuildMS, RequestSignNS: requestSignMS, RequestedMode: "auto", SelectedMode: selected.Mode, Constraints: ccs.GetNbConstraints(), CompileMS: compileMS, CompileNS: compileElapsed.Nanoseconds(), SetupNS: int64Ptr(setupElapsed.Nanoseconds()), WitnessMS: witnessMS, WitnessNS: witnessElapsed.Nanoseconds(), ProveMS: proveMS, ProveNS: proveElapsed.Nanoseconds(), VerifyMS: verifyMS, VerifyNS: verifyElapsed.Nanoseconds(), ReceiptSignNS: receiptSignNS, ReceiptVerifyNS: receiptVerifyNS, ProofBytes: pb.Len(), PublicInputBytes: ub.Len(), PKBytes: pkb.Len(), VKBytes: vkb.Len(), PeakRSSMB: maxRSS(setupRSS, batchRSS), Status: "shape_specialized_setup_and_proof_pass"}
		setV2Metadata(&r, batch)
		addProvenance(&r, batch, output)
		if n == 0 {
			r.SetupMS = &setupMS
			if selectorMS > 0 {
				r.SelectorMS = &selectorMS
			}
		}
		if err = enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// RunPackedBatch is the fixed-q, one-row-per-product comparator on the same
// heterogeneous fixture used by RunSparseBatch.
func RunPackedBatch(batches []workload.Batch, output string) error {
	if len(batches) == 0 {
		return fmt.Errorf("empty packed workload")
	}
	first := batches[0]
	selected, selectorMS, err := cachedDispatch(16, len(first.Products), first.U, first.H, first.Q)
	if err != nil {
		return err
	}
	runtime.GC()
	debug.FreeOSMemory()
	q := first.Q
	m := len(first.Products)
	tmpl := &circuit.ClassCircuit{A: make([]frontend.Variable, 16), Classes: make([][]frontend.Variable, m), C: make([]frontend.Variable, m), Z: make([]frontend.Variable, m)}
	for j := range tmpl.Classes {
		tmpl.Classes[j] = make([]frontend.Variable, q)
	}
	shapeJSON, _ := json.Marshal(struct{ S, M, Q int }{16, m, q})
	ph := sha256.Sum256(append([]byte("MedProof/packed-shape/v1\x00"), shapeJSON...))
	stopSetupRSS := startPeakRSSSampling()
	cs := time.Now()
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, tmpl)
	if e != nil {
		return e
	}
	compileElapsed := time.Since(cs)
	compileMS := compileElapsed.Milliseconds()
	ss := time.Now()
	pk, vk, e := groth16.Setup(ccs)
	if e != nil {
		return e
	}
	setupElapsed := time.Since(ss)
	setupMS := setupElapsed.Milliseconds()
	setupRSS := stopSetupRSS()
	var pkb, vkb bytes.Buffer
	_, _ = pk.WriteTo(&pkb)
	_, _ = vk.WriteTo(&vkb)
	if e = os.MkdirAll(filepath.Dir(output), 0755); e != nil {
		return e
	}
	f, e := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if first.Rep > 0 {
		if err := warmupPacked(first, selected, ccs, pk, vk); err != nil {
			return fmt.Errorf("packed warmup failed: %w", err)
		}
	}
	for n, batch := range batches {
		stopBatchRSS := startPeakRSSSampling()
		dq, digestText, requestBuildMS, requestSignMS, e := requestBindingForRun(batch, 16, selected)
		if e != nil {
			return e
		}
		if len(batch.Products) != m || batch.Q != q {
			return fmt.Errorf("packed workload shape changed")
		}
		a, e := circuit.BuildPackedUncompressedWitness([]uint16{1, 3, 5}, batch.Products, 16, q, dq, big.NewInt(batch.Seed+20000), big.NewInt(batch.Seed+30000))
		if e != nil {
			return e
		}
		w, witnessNS, e := newWitnessForRun(a, batch)
		witnessElapsed := time.Duration(witnessNS)
		wm := witnessElapsed.Milliseconds()
		if e != nil {
			return e
		}
		ps := time.Now()
		proof, e := groth16.Prove(ccs, pk, w)
		proveElapsed := time.Since(ps)
		pm := proveElapsed.Milliseconds()
		if e != nil {
			return e
		}
		pub, e := w.Public()
		if e != nil {
			return e
		}
		verifyNS, verr := verifyForRun(proof, vk, pub, batch)
		verifyElapsed := time.Duration(verifyNS)
		e = verr
		vm := verifyElapsed.Milliseconds()
		if e != nil {
			return e
		}
		var pb, ub bytes.Buffer
		_, _ = proof.WriteTo(&pb)
		_, _ = pub.WriteTo(&ub)
		batchRSS := stopBatchRSS()
		receiptSignNS, receiptVerifyNS := int64(0), int64(0)
		if batch.Rep > 0 {
			receiptSignNS, receiptVerifyNS, e = receiptTiming(batch, digestText, a)
			if e != nil {
				return e
			}
		}
		r := Record{RunID: time.Now().UTC().Format("20060102T150405.000000000Z"), Seed: batch.Seed, WorkloadSource: batch.Source, Backend: "Groth16", Curve: "BN254", Variant: "packed_uncompressed_fixed_q", Mode: "packed", S: 16, M: m, MSupported: m, U: batch.U, L: batch.L, H: batch.H, Q: q, TD: m, Alpha: batch.Alpha, ProfileHash: hex.EncodeToString(ph[:]), RequestDigest: &digestText, RequestBuildNS: requestBuildMS, RequestSignNS: requestSignMS, RequestedMode: "auto", SelectedMode: selected.Mode, Constraints: ccs.GetNbConstraints(), CompileMS: compileMS, CompileNS: compileElapsed.Nanoseconds(), SetupNS: int64Ptr(setupElapsed.Nanoseconds()), WitnessMS: wm, WitnessNS: witnessElapsed.Nanoseconds(), ProveMS: pm, ProveNS: proveElapsed.Nanoseconds(), VerifyMS: vm, VerifyNS: verifyElapsed.Nanoseconds(), ReceiptSignNS: receiptSignNS, ReceiptVerifyNS: receiptVerifyNS, ProofBytes: pb.Len(), PublicInputBytes: ub.Len(), PKBytes: pkb.Len(), VKBytes: vkb.Len(), PeakRSSMB: maxRSS(setupRSS, batchRSS), Status: "prove_verify_pass"}
		setV2Metadata(&r, batch)
		addProvenance(&r, batch, output)
		if n == 0 {
			r.SetupMS = &setupMS
			if selectorMS > 0 {
				r.SelectorMS = &selectorMS
			}
		}
		if e = enc.Encode(r); e != nil {
			return e
		}
	}
	return nil
}
