package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"medproof/internal/bench"
	"medproof/internal/registry"
	"medproof/internal/workload"
)

type plan struct {
	Status             string             `json:"status"`
	E1Profiles         []registry.Profile `json:"e1_profiles"`
	E2MedProofProfiles []registry.Profile `json:"e2_medproof_profiles"`
	E1SetupCount       int                `json:"e1_setup_count"`
	E2SetupCount       int                `json:"e2_setup_count"`
	E2BaselineStatus   []string           `json:"e2_baseline_status"`
	SmokeMeasurements  string             `json:"smoke_measurements"`
	FullRunsExecuted   bool               `json:"full_runs_executed"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "medproof:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: medproof {build|test|smoke|plan|report|dataset-audit|setup-profile|exp1|exp2|exp1-v2|exp2-v2|enrich-run}")
	}
	switch args[0] {
	case "build":
		return goCommand("build", "./...")
	case "test":
		return goCommand("test", "./...", "-count=1")
	case "smoke":
		if err := goCommand("test", "./internal/poseidon", "-run", "TestPoseidon(NativeAndCircuit|NonzeroDomain)Vector", "-count=1", "-v"); err != nil {
			return err
		}
		return goCommand("test", "./internal/circuit", "-run", "TestGroth16(Ingredient|Class)BranchSmoke", "-count=1", "-v")
	case "plan":
		p := buildPlan()
		if err := writeJSON(filepath.Join("reports", "implementation_plan.json"), p); err != nil {
			return err
		}
		fmt.Printf("E1 MedProof profile shapes: %d; expected Groth16 setup count: %d\n", len(p.E1Profiles), p.E1SetupCount)
		fmt.Printf("E2 MedProof profile shapes: %d; expected setup count: %d\n", len(p.E2MedProofProfiles), p.E2SetupCount)
		fmt.Println("E2 baseline setup shapes are reported in e2_run.json; each sparse row-width shape has its own measured Setup.")
		return nil
	case "report":
		return reportSmoke()
	case "dataset-audit":
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		a, err := workload.FetchJClinicalAudit(ctx, nil)
		if err != nil {
			return err
		}
		if err := writeJSON(filepath.Join("reports", "jclinical_aggregate_audit.json"), a); err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(a)
	case "setup-profile":
		return setupProfile(args[1:])
	case "exp1", "exp2":
		if !hasArg(args[1:], "--approved") {
			return errors.New("full E1/E2 runner requires the explicit --approved flag")
		}
		if hasArg(args[1:], "--rxnorm") {
			if err := os.Setenv(workload.RxNormWorkloadEnv, filepath.Join("data", "public_sources", "rxnorm_prescribable_20261005_workloads.json")); err != nil {
				return err
			}
		}
		return runExperiment(args[0])
	case "exp1-v2", "exp2-v2":
		if !hasArg(args[1:], "--approved") {
			return errors.New("v2 full runner requires explicit --approved")
		}
		if hasArg(args[1:], "--rxnorm") {
			if err := os.Setenv(workload.RxNormWorkloadEnv, filepath.Join("data", "public_sources", "rxnorm_prescribable_20261005_workloads.json")); err != nil {
				return err
			}
		}
		return runExperimentV2(args[0], hasArg(args[1:], "--smoke"))
	case "enrich-run":
		if len(args) < 3 {
			return errors.New("usage: medproof enrich-run <jsonl> <manifest>")
		}
		return bench.EnrichRunFile(args[1], args[2])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runExperiment(which string) error {
	seeds := []int64{11, 23, 37, 53, 71}
	if which == "exp2" {
		return runE2Comparisons(seeds)
	}
	outDir := "E1"
	stamp := time.Now().UTC().Format("20060102T150405Z")
	out := filepath.Join("results", "full", outDir+"_"+stamp+".jsonl")
	manifest := "configs/e1_manifest.json"
	if os.Getenv(workload.RxNormWorkloadEnv) != "" {
		manifest = "configs/e1_rxnorm_manifest.json"
	}
	manifestHash, err := bench.ManifestHash(manifest)
	if err != nil {
		return err
	}
	type e1Case struct {
		factor        string
		s, m, u, h, q int
	}
	cases := []e1Case{}
	for _, s := range []int{16, 32, 64, 128} {
		cases = append(cases, e1Case{"S_scaling", s, 8, 8, 4, 2})
	}
	for _, m := range []int{4, 8, 16, 32} {
		cases = append(cases, e1Case{"m_scaling", 16, m, 8, 4, 2})
	}
	for _, v := range []struct{ u, h int }{{4, 1}, {8, 4}, {16, 8}} {
		cases = append(cases, e1Case{"reuse_sweep", 16, 8, v.u, v.h, 4})
	}
	for _, q := range []int{1, 2, 4} {
		cases = append(cases, e1Case{"q_sweep", 16, 8, 8, 8, q})
	}
	capacityCases := []e1Case{
		{"capacity_boundary", 16, 4, 4, 4, 1},
		{"capacity_boundary", 16, 8, 8, 4, 2},
		{"capacity_boundary", 32, 16, 16, 8, 2},
		{"capacity_boundary", 64, 32, 32, 8, 4},
		{"capacity_boundary", 128, 32, 32, 8, 4},
	}
	if os.Getenv(workload.RxNormWorkloadEnv) != "" {
		capacityCases[3] = e1Case{"capacity_boundary", 64, 32, 16, 8, 2}
		capacityCases[4] = e1Case{"capacity_boundary", 128, 32, 16, 8, 2}
	}
	for _, v := range capacityCases {
		cases = append(cases, v)
	}
	total := 2 * len(cases)
	fmt.Printf("Starting %s: %d workload/mode profiles x %d seeds; output %s\n", which, total, len(seeds), out)
	profileIndex := 0
	for _, c := range cases {
		for _, mode := range []string{"ingredient", "class"} {
			profileIndex++
			var p registry.Profile
			if mode == "ingredient" {
				p = registry.Profile{Mode: mode, S: c.s, TU: roundCapacity(c.u), TM: roundCapacity(c.m)}
			} else {
				p = registry.Profile{Mode: mode, S: c.s, TD: roundCapacity(c.h), Q: c.q}
			}
			variant := fmt.Sprintf("MedProof-V13-E1-%s-%s", c.factor, mode)
			fmt.Printf("[%d/%d] %s %s S=%d m=%d u=%d h=%d q=%d\n", profileIndex, total, c.factor, mode, c.s, c.m, c.u, c.h, c.q)
			if err := bench.RunProfileShape(p, seeds, out, variant, c.m, c.u, c.h, c.q); err != nil {
				return fmt.Errorf("%s %s failed: %w", c.factor, mode, err)
			}
		}
	}
	if err := bench.EnrichRunFile(out, manifest); err != nil {
		return err
	}
	return writeJSON(filepath.Join("reports", strings.ToLower(outDir)+"_run.json"), map[string]any{"manifest": manifest, "manifest_sha256": manifestHash, "profiles": total, "seeds": seeds, "records": total * len(seeds), "output": out, "status": "measured_e1_manifest_workload_matrix"})
}

func runE2Comparisons(seeds []int64) error {
	manifest := "configs/e2_manifest.json"
	if os.Getenv(workload.RxNormWorkloadEnv) != "" {
		manifest = "configs/e2_rxnorm_manifest.json"
	}
	manifestHash, e := bench.ManifestHash(manifest)
	if e != nil {
		return e
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	out := filepath.Join("results", "full", "E2_compare_"+stamp+".jsonl")
	workloads := []struct {
		name       string
		m, u, h, q int
	}{
		{"single_ingredient_low_reuse", 8, 8, 8, 1},
		{"combination_high_ingredient_reuse", 8, 8, 4, 4},
		{"complete_class_reuse", 8, 8, 2, 4},
		{"mode_boundary_candidate", 8, 8, 4, 2},
	}
	fmt.Printf("E2 comparison run: %d workloads x %d seeds; proof results at %s\n", len(workloads), len(seeds), out)
	for wi, w := range workloads {
		fmt.Printf("[%d/%d] %s\n", wi+1, len(workloads), w.name)
		// Each method receives the same deterministic workload seed and alert set.
		ip := registry.Profile{Mode: "ingredient", S: 16, TU: 8, TM: 8}
		cp := registry.Profile{Mode: "class", S: 16, TD: roundCapacity(w.h), Q: w.q}
		if e := bench.RunProfileShape(ip, seeds, out, "ingredient_only", w.m, w.u, w.h, w.q); e != nil {
			return fmt.Errorf("%s ingredient_only: %w", w.name, e)
		}
		if e := bench.RunProfileShape(cp, seeds, out, "class_only", w.m, w.u, w.h, w.q); e != nil {
			return fmt.Errorf("%s class_only: %w", w.name, e)
		}
		batches := make([]workload.Batch, 0, len(seeds))
		for _, seed := range seeds {
			b, e := workload.GenerateFromSource(seed, w.m, w.u, w.h, w.q)
			if e != nil {
				return e
			}
			batches = append(batches, b)
		}
		// Packed uncompressed uses those identical ordered products but keeps a
		// separate result row per product and disables complete-set deduplication.
		if e := bench.RunPackedBatch(batches, out); e != nil {
			return fmt.Errorf("%s packed_uncompressed: %w", w.name, e)
		}
		if e := bench.RunSparseBatch(batches, out); e != nil {
			return fmt.Errorf("%s sparse_packed: %w", w.name, e)
		}
		if e := bench.RunIndependentBatch(batches, out); e != nil {
			return fmt.Errorf("%s independent_zkp: %w", w.name, e)
		}
		dispatch, e := bench.SelectByCompiledConstraints(16, w.m, w.u, w.h, w.q)
		if e != nil {
			return e
		}
		if e = bench.RunProfileShape(dispatch, seeds, out, "medproof_dispatch", w.m, w.u, w.h, w.q); e != nil {
			return fmt.Errorf("%s dispatcher: %w", w.name, e)
		}
	}
	// Add a fixed heterogeneous-width fixture so sparse work is measured on the
	// exact same batches as ingredient, class, packed, independent, and dispatch.
	var mixed []workload.Batch
	for _, seed := range seeds {
		b, e := workload.GenerateHeterogeneousFromSource(seed)
		if e != nil {
			return e
		}
		mixed = append(mixed, b)
	}
	if e := bench.RunProfileBatches(registry.Profile{Mode: "ingredient", S: 16, TU: 8, TM: 8}, mixed, out, "ingredient_only_heterogeneous"); e != nil {
		return e
	}
	if e := bench.RunProfileBatches(registry.Profile{Mode: "class", S: 16, TD: 4, Q: 4}, mixed, out, "class_only_heterogeneous"); e != nil {
		return e
	}
	if e := bench.RunPackedBatch(mixed, out); e != nil {
		return e
	}
	if e := bench.RunSparseBatch(mixed, out); e != nil {
		return e
	}
	if e := bench.RunIndependentBatch(mixed, out); e != nil {
		return e
	}
	dispatch, e := bench.SelectByCompiledConstraints(16, 8, 8, 4, 4)
	if e != nil {
		return e
	}
	if e = bench.RunProfileBatches(dispatch, mixed, out, "medproof_dispatch_heterogeneous"); e != nil {
		return e
	}
	if e = bench.EnrichRunFile(out, manifest); e != nil {
		return e
	}
	return writeJSON(filepath.Join("reports", "e2_run.json"), map[string]any{"manifest": manifest, "manifest_sha256": manifestHash, "workloads": len(workloads) + 1, "seeds": seeds, "records": (len(workloads) + 1) * len(seeds) * 6, "measured_variants": []string{"independent_zkp", "packed_uncompressed", "class_only", "ingredient_only", "sparse_packed_shape_specialized", "medproof_dispatch"}, "generic_optimized": "same relation as MedProof branch; tie by construction", "output": out, "status": "comparison_measured_on_uniform_and_heterogeneous_fixtures"})
}

type e1V2Job struct {
	factor, dimension    string
	level, s, m, u, h, q int
	mode                 string
	profile              registry.Profile
}

type e2V2Job struct {
	workloadID, variant string
	batches             []workload.Batch
	run                 func([]workload.Batch, string) error
}

func runExperimentV2(which string, smoke bool) error {
	seeds := []int64{11, 23, 37, 53, 71}
	base := filepath.Join("results", "v2_20261031", "results")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	calibrator, err := bench.NewCalibrationRunner()
	if err != nil {
		return err
	}
	calPath := filepath.Join("results", "v2_20261031", "calibration.csv")
	if smoke {
		seedSet := []int64{11}
		if which == "exp1-v2" {
			p := registry.Profile{Mode: "ingredient", S: 16, TU: 8, TM: 8}
			out := filepath.Join(base, "E1_smoke.jsonl")
			_ = os.Remove(out)
			if err := bench.RunProfileShapeRepeated(p, seedSet, out, "MedProof-V13-E1-smoke", 8, 8, 4, 2, 1, 0, "smoke:S=16"); err != nil {
				return err
			}
			if err := bench.EnrichRunFile(out, "configs/e1_rxnorm_manifest.json"); err != nil {
				return err
			}
			return writeJSON(filepath.Join("results", "v2_20261031", "reports", "e1_smoke.json"), map[string]any{"records": 1, "seed": 11, "reps": 1, "status": "smoke_pass"})
		}
		b, err := workload.GenerateFromSource(11, 8, 8, 8, 1)
		if err != nil {
			return err
		}
		b.Rep, b.WorkloadID, b.RunOrder = 1, "W1", 0
		out := filepath.Join(base, "E2_smoke.jsonl")
		_ = os.Remove(out)
		bs := []workload.Batch{b}
		ip := registry.Profile{Mode: "ingredient", S: 16, TU: 8, TM: 8}
		cp := registry.Profile{Mode: "class", S: 16, TD: 8, Q: 1}
		if err = bench.RunProfileBatches(ip, bs, out, "ingredient_only"); err != nil {
			return err
		}
		if err = bench.RunProfileBatches(cp, bs, out, "class_only"); err != nil {
			return err
		}
		if err = bench.RunPackedBatch(bs, out); err != nil {
			return err
		}
		if err = bench.RunSparseBatch(bs, out); err != nil {
			return err
		}
		if err = bench.RunIndependentBatch(bs, out); err != nil {
			return err
		}
		dispatch, err := bench.SelectByCompiledConstraints(16, 8, 8, 8, 1)
		if err != nil {
			return err
		}
		if err = bench.RunProfileBatches(dispatch, bs, out, "medproof_dispatch"); err != nil {
			return err
		}
		if err = bench.EnrichRunFile(out, "configs/e2_rxnorm_manifest.json"); err != nil {
			return err
		}
		return writeJSON(filepath.Join("results", "v2_20261031", "reports", "e2_smoke.json"), map[string]any{"records": 6, "seed": 11, "reps": 1, "status": "smoke_pass_all_methods"})
	}
	if which == "exp1-v2" {
		manifest := "configs/e1_rxnorm_manifest.json"
		if os.Getenv(workload.RxNormWorkloadEnv) == "" {
			manifest = "configs/e1_manifest.json"
		}
		mh, err := bench.ManifestHash(manifest)
		if err != nil {
			return err
		}
		jobs := make([]e1V2Job, 0, 38)
		add := func(factor, dimension string, level, s, m, u, h, q int) {
			for _, mode := range []string{"ingredient", "class"} {
				p := registry.Profile{Mode: mode, S: s}
				if mode == "ingredient" {
					p.TU = roundCapacity(u)
					p.TM = roundCapacity(m)
				} else {
					p.TD = roundCapacity(h)
					p.Q = q
				}
				jobs = append(jobs, e1V2Job{factor: factor, dimension: dimension, level: level, s: s, m: m, u: u, h: h, q: q, mode: mode, profile: p})
			}
		}
		for _, s := range []int{16, 32, 64, 128} {
			add("S_scaling", "S", s, s, 8, 8, 4, 2)
		}
		for _, m := range []int{4, 8, 16, 32} {
			add("m_scaling", "m", m, 16, m, 8, 4, 2)
		}
		for _, v := range []struct{ u, h int }{{4, 1}, {8, 4}, {16, 8}} {
			add("reuse_sweep", "u", v.u, 16, 8, v.u, v.h, 4)
		}
		for _, q := range []int{1, 2, 4} {
			add("q_sweep", "q", q, 16, 8, 8, 8, q)
		}
		caps := []e1V2Job{{factor: "capacity_boundary", dimension: "S", level: 16, s: 16, m: 4, u: 4, h: 4, q: 1}, {factor: "capacity_boundary", dimension: "S", level: 16, s: 16, m: 8, u: 8, h: 4, q: 2}, {factor: "capacity_boundary", dimension: "S", level: 32, s: 32, m: 16, u: 16, h: 8, q: 2}, {factor: "capacity_boundary", dimension: "S", level: 64, s: 64, m: 32, u: 16, h: 8, q: 2}, {factor: "capacity_boundary", dimension: "S", level: 128, s: 128, m: 32, u: 16, h: 8, q: 2}}
		for _, c := range caps {
			for _, mode := range []string{"ingredient", "class"} {
				p := registry.Profile{Mode: mode, S: c.s}
				if mode == "ingredient" {
					p.TU = roundCapacity(c.u)
					p.TM = roundCapacity(c.m)
				} else {
					p.TD = roundCapacity(c.h)
					p.Q = c.q
				}
				c.mode = mode
				c.profile = p
				jobs = append(jobs, c)
			}
		}
		rng := rand.New(rand.NewSource(2026))
		rng.Shuffle(len(jobs), func(i, j int) { jobs[i], jobs[j] = jobs[j], jobs[i] })
		out := filepath.Join(base, "E1_raw.jsonl")
		_ = os.Remove(out)
		_ = os.Remove(calPath)
		for i, j := range jobs {
			order := i + 1
			id := fmt.Sprintf("%s:%s=%d", j.factor, j.dimension, j.level)
			if j.factor == "capacity_boundary" {
				id = fmt.Sprintf("capacity_boundary:S=%d,m=%d,u=%d,h=%d,q=%d", j.s, j.m, j.u, j.h, j.q)
			}
			variant := fmt.Sprintf("MedProof-V13-E1-%s-%s", j.factor, j.mode)
			fmt.Printf("E1 v2 profile %d/%d %s rep=3+warmup\n", order, len(jobs), id+":"+j.mode)
			if err := bench.RunProfileShapeRepeated(j.profile, seeds, out, variant, j.m, j.u, j.h, j.q, 3, order, id); err != nil {
				return fmt.Errorf("E1 v2 profile %s %s: %w", id, j.mode, err)
			}
			if order%5 == 0 {
				if _, err := calibrator.Run(calPath, order); err != nil {
					return err
				}
			}
		}
		if len(jobs)%5 != 0 {
			if _, err := calibrator.Run(calPath, len(jobs)); err != nil {
				return err
			}
		}
		if err := bench.EnrichRunFile(out, manifest); err != nil {
			return err
		}
		return writeJSON(filepath.Join("results", "v2_20261031", "reports", "e1_run.json"), map[string]any{"manifest": manifest, "manifest_sha256": mh, "profiles": len(jobs), "seeds": seeds, "reps": 3, "records": len(jobs) * len(seeds) * 3, "output": out, "randomization_seed": 2026, "warmup": "one prove+verify per profile, excluded", "status": "measured_v2_e1"})
	}
	manifest := "configs/e2_rxnorm_manifest.json"
	if os.Getenv(workload.RxNormWorkloadEnv) == "" {
		manifest = "configs/e2_manifest.json"
	}
	mh, err := bench.ManifestHash(manifest)
	if err != nil {
		return err
	}
	workDefs := []struct {
		id         string
		m, u, h, q int
	}{{"W1", 8, 8, 8, 1}, {"W2", 8, 8, 4, 4}, {"W3", 8, 8, 2, 4}, {"W4", 8, 8, 4, 2}}
	allBatches := map[string][]workload.Batch{}
	for _, w := range workDefs {
		bs := make([]workload.Batch, 0, len(seeds))
		for _, seed := range seeds {
			b, e := workload.GenerateFromSource(seed, w.m, w.u, w.h, w.q)
			if e != nil {
				return e
			}
			bs = append(bs, b)
		}
		allBatches[w.id] = bs
	}
	mixed := make([]workload.Batch, 0, len(seeds))
	for _, seed := range seeds {
		b, e := workload.GenerateHeterogeneousFromSource(seed)
		if e != nil {
			return e
		}
		mixed = append(mixed, b)
	}
	allBatches["W5"] = mixed
	jobs := make([]e2V2Job, 0, 30)
	for _, w := range workDefs {
		w := w
		bs := allBatches[w.id]
		ip := registry.Profile{Mode: "ingredient", S: 16, TU: roundCapacity(w.u), TM: roundCapacity(w.m)}
		cp := registry.Profile{Mode: "class", S: 16, TD: roundCapacity(w.h), Q: w.q}
		dispatch, e := bench.SelectByCompiledConstraints(16, w.m, w.u, w.h, w.q)
		if e != nil {
			return e
		}
		jobs = append(jobs, e2V2Job{workloadID: w.id, variant: "ingredient_only", batches: bs, run: func(b []workload.Batch, o string) error { return bench.RunProfileBatches(ip, b, o, "ingredient_only") }})
		jobs = append(jobs, e2V2Job{workloadID: w.id, variant: "class_only", batches: bs, run: func(b []workload.Batch, o string) error { return bench.RunProfileBatches(cp, b, o, "class_only") }})
		jobs = append(jobs, e2V2Job{workloadID: w.id, variant: "packed_uncompressed_fixed_q", batches: bs, run: bench.RunPackedBatch})
		jobs = append(jobs, e2V2Job{workloadID: w.id, variant: "sparse_packed_shape_specialized", batches: bs, run: bench.RunSparseBatch})
		jobs = append(jobs, e2V2Job{workloadID: w.id, variant: "independent_zkp", batches: bs, run: bench.RunIndependentBatch})
		jobs = append(jobs, e2V2Job{workloadID: w.id, variant: "medproof_dispatch", batches: bs, run: func(b []workload.Batch, o string) error {
			return bench.RunProfileBatches(dispatch, b, o, "medproof_dispatch")
		}})
	}
	{
		bs := allBatches["W5"]
		ip := registry.Profile{Mode: "ingredient", S: 16, TU: 8, TM: 8}
		cp := registry.Profile{Mode: "class", S: 16, TD: 4, Q: 4}
		dispatch, e := bench.SelectByCompiledConstraints(16, 8, 8, 4, 4)
		if e != nil {
			return e
		}
		jobs = append(jobs, e2V2Job{workloadID: "W5", variant: "ingredient_only", batches: bs, run: func(b []workload.Batch, o string) error {
			return bench.RunProfileBatches(ip, b, o, "ingredient_only_heterogeneous")
		}})
		jobs = append(jobs, e2V2Job{workloadID: "W5", variant: "class_only", batches: bs, run: func(b []workload.Batch, o string) error {
			return bench.RunProfileBatches(cp, b, o, "class_only_heterogeneous")
		}})
		jobs = append(jobs, e2V2Job{workloadID: "W5", variant: "packed_uncompressed_fixed_q", batches: bs, run: bench.RunPackedBatch})
		jobs = append(jobs, e2V2Job{workloadID: "W5", variant: "sparse_packed_shape_specialized", batches: bs, run: bench.RunSparseBatch})
		jobs = append(jobs, e2V2Job{workloadID: "W5", variant: "independent_zkp", batches: bs, run: bench.RunIndependentBatch})
		jobs = append(jobs, e2V2Job{workloadID: "W5", variant: "medproof_dispatch", batches: bs, run: func(b []workload.Batch, o string) error {
			return bench.RunProfileBatches(dispatch, b, o, "medproof_dispatch_heterogeneous")
		}})
	}
	rng := rand.New(rand.NewSource(2026))
	rng.Shuffle(len(jobs), func(i, j int) { jobs[i], jobs[j] = jobs[j], jobs[i] })
	out := filepath.Join(base, "E2_raw.jsonl")
	_ = os.Remove(out)
	for i, j := range jobs {
		order := i + 1
		repeated, e := bench.RepeatBatches(j.batches, 3, order, j.workloadID)
		if e != nil {
			return e
		}
		fmt.Printf("E2 v2 profile %d/%d %s %s rep=3+warmup\n", order, len(jobs), j.workloadID, j.variant)
		if e = j.run(repeated, out); e != nil {
			return fmt.Errorf("E2 v2 %s %s: %w", j.workloadID, j.variant, e)
		}
		if order%5 == 0 {
			if _, e = calibrator.Run(calPath, 38+order); e != nil {
				return e
			}
		}
	}
	if len(jobs)%5 != 0 {
		if _, err = calibrator.Run(calPath, 38+len(jobs)); err != nil {
			return err
		}
	}
	if err = bench.EnrichRunFile(out, manifest); err != nil {
		return err
	}
	return writeJSON(filepath.Join("results", "v2_20261031", "reports", "e2_run.json"), map[string]any{"manifest": manifest, "manifest_sha256": mh, "workloads": 5, "methods": 6, "seeds": seeds, "reps": 3, "records": len(jobs) * len(seeds) * 3, "output": out, "randomization_seed": 2026, "warmup": "one prove+verify per profile, excluded", "status": "measured_v2_e2"})
}

func goCommand(args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func roundCapacity(n int) int {
	for _, v := range []int{4, 8, 16, 32} {
		if n <= v {
			return v
		}
	}
	return 0
}
func profileKey(p registry.Profile) string { h, _ := registry.HashProfile(p); return h }
func buildPlan() plan {
	set := map[string]registry.Profile{}
	add := func(p registry.Profile) {
		if p.S < 16 || roundCapacity(p.TU) > 32 || roundCapacity(p.TM) > 32 || roundCapacity(p.TD) > 32 || p.Mode == "ingredient" && (p.TU == 0 || p.TM == 0) || p.Mode == "class" && (p.TD == 0 || p.Q == 0) {
			return
		}
		if p.Mode == "ingredient" {
			p.TU = roundCapacity(p.TU)
			p.TM = roundCapacity(p.TM)
		} else {
			p.TD = roundCapacity(p.TD)
			// q is a workload parameter, not a registered power-of-two tier.
		}
		set[profileKey(p)] = p
	}
	for _, s := range []int{16, 32, 64, 128} {
		add(registry.Profile{Mode: "ingredient", S: s, TU: 8, TM: 8})
		add(registry.Profile{Mode: "class", S: s, TD: 8, Q: 4})
	}
	for _, m := range []int{4, 8, 16, 32} {
		h := m
		if h > 8 {
			h = 8
		}
		add(registry.Profile{Mode: "ingredient", S: 16, TU: 8, TM: m})
		add(registry.Profile{Mode: "class", S: 16, TD: h, Q: 4})
	}
	for _, v := range []struct{ u, h int }{{4, 1}, {8, 4}, {16, 8}} {
		add(registry.Profile{Mode: "ingredient", S: 16, TU: v.u, TM: 8})
		add(registry.Profile{Mode: "class", S: 16, TD: v.h, Q: 4})
	}
	for _, q := range []int{1, 2, 4} {
		add(registry.Profile{Mode: "class", S: 16, TD: 8, Q: q})
	}
	for _, capacity := range []int{4, 8, 16, 32} {
		add(registry.Profile{Mode: "ingredient", S: 16, TU: capacity, TM: capacity})
		add(registry.Profile{Mode: "class", S: 16, TD: capacity, Q: 4})
	}
	e1 := make([]registry.Profile, 0, len(set))
	for _, p := range set {
		e1 = append(e1, p)
	}
	sort.Slice(e1, func(i, j int) bool { return profileKey(e1[i]) < profileKey(e1[j]) })
	e2 := make([]registry.Profile, 0)
	for _, s := range []int{16} {
		for _, work := range []struct{ m, u, h, q int }{{8, 8, 8, 1}, {8, 8, 4, 4}, {8, 8, 2, 4}, {8, 8, 4, 2}} {
			e2 = append(e2, registry.Profile{Mode: "ingredient", S: s, TU: roundCapacity(work.u), TM: roundCapacity(work.m)}, registry.Profile{Mode: "class", S: s, TD: roundCapacity(work.h), Q: work.q})
		}
	}
	dedup := map[string]registry.Profile{}
	for _, p := range e2 {
		dedup[profileKey(p)] = p
	}
	e2 = e2[:0]
	for _, p := range dedup {
		e2 = append(e2, p)
	}
	sort.Slice(e2, func(i, j int) bool { return profileKey(e2[i]) < profileKey(e2[j]) })
	return plan{Status: "profile_plan_with_executable_runner", E1Profiles: e1, E2MedProofProfiles: e2, E1SetupCount: len(e1), E2SetupCount: len(e2), E2BaselineStatus: []string{"independent_zkp:executable_batch_aggregate", "packed_uncompressed:fixed_q_product_rows", "class_only:executable", "ingredient_only:executable", "sparse_packed:shape_specialized_setup_included", "generic_optimized:same_circuit_tie", "medproof_dispatch:compiled_constraint_selector"}, SmokeMeasurements: "E1/E2 outputs in results/full; peak RSS via Windows working-set sampling", FullRunsExecuted: true}
}

func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0o755); e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func reportSmoke() error {
	paths := []string{filepath.Join("results", "smoke", "ingredient.json"), filepath.Join("results", "smoke", "class.json")}
	file, err := os.Create(filepath.Join("results", "smoke", "smoke.csv"))
	if err != nil {
		return err
	}
	defer file.Close()
	w := csv.NewWriter(file)
	defer w.Flush()
	if err = w.Write([]string{"mode", "S", "m", "r1cs_constraints", "compile_ms", "setup_ms", "witness_ms", "prove_ms", "verify_ms", "proof_bytes", "public_input_bytes", "pk_bytes", "vk_bytes", "peak_rss_mb", "status"}); err != nil {
		return err
	}
	for _, path := range paths {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var r map[string]any
		if e = json.Unmarshal(b, &r); e != nil {
			return e
		}
		get := func(k string) string {
			if r[k] == nil {
				return ""
			}
			return fmt.Sprint(r[k])
		}
		row := []string{get("mode"), get("S"), get("m"), get("r1cs_constraints"), get("compile_ms"), get("setup_ms"), get("witness_ms"), get("prove_ms"), get("verify_ms"), get("proof_bytes"), get("public_input_bytes"), get("pk_bytes"), get("vk_bytes"), get("peak_rss_mb"), get("status")}
		if e = w.Write(row); e != nil {
			return e
		}
	}
	fmt.Println("Wrote smoke CSV. Full E1/E2 measurements and plots are maintained by scripts/report_experiments.py.")
	return nil
}

func setupProfile(args []string) error {
	values := map[string]int{}
	mode := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--mode" && i+1 < len(args) {
			i++
			mode = args[i]
			continue
		}
		if strings.HasPrefix(args[i], "--") {
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for %s", args[i])
			}
			n, e := strconv.Atoi(args[i+1])
			if e != nil {
				return e
			}
			values[args[i]] = n
			i++
		}
	}
	p := registry.Profile{Mode: mode, S: values["--S"], TU: values["--tu"], TM: values["--tm"], TD: values["--td"], Q: values["--q"]}
	entry, err := registry.SetupProfile(p, filepath.Join("keys"))
	if err != nil {
		return err
	}
	path := filepath.Join("configs", "registry.json")
	r := registry.Registry{Version: "medproof-registry-v1"}
	if old, e := registry.Load(path); e == nil {
		r = old
	}
	kept := r.Entries[:0]
	for _, e := range r.Entries {
		if e.ProfileHash != entry.ProfileHash {
			kept = append(kept, e)
		}
	}
	r.Entries = append(kept, entry)
	if err := registry.Save(path, r); err != nil {
		return err
	}
	fmt.Printf("registered %s constraints=%d key=%s\n", entry.ProfileHash, entry.ConstraintCount, entry.VerificationKeyHash)
	return nil
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
