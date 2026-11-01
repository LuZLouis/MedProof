# MedProof prototype

MedProof is a research prototype for allergy-aware medication screening using Groth16 proofs over BN254. It contains the circuit definitions, witness builders, protocol and registry code, synthetic workload generator, benchmark runner, and tests.

This repository contains **source code only**. It does not include experiment result files, clinical records, RxNorm source data, generated workloads, keys, or the paper. An optional RxNorm workload preparation script is included for users who have the required source data.

## Status and intended use

This is experimental research software, not a clinical product. It has not been validated for patient care or deployment. The cryptographic encoding profile is documented in [`docs/crypto_profile.md`](docs/crypto_profile.md); it includes prototype choices beyond what the paper fully specifies and requires independent review before any security or clinical claims.

## Requirements

- Go 1.26.10 (matches `go.mod`)
- CPU; no GPU or model training is used
- Network access for the first Go module download, unless dependencies are already cached

## Build and run

```sh
go build ./cmd/medproof
go test ./...
go run ./cmd/medproof smoke
go run ./cmd/medproof plan
```

The CLI also supports benchmark, setup, reporting, and dataset-audit commands. Run it without arguments for the command list. Full E1/E2 runs require an explicit `--approved` flag and can be computationally expensive. RxNorm-backed runs also require a locally supplied, appropriately licensed workload file; no RxNorm dataset is distributed here. Without that file, the workload generator uses deterministic synthetic fixtures.

On Windows, `scripts/bootstrap-go.ps1` can install the pinned Go toolchain after verifying its archive checksum. `scripts/prepare_rxnorm_workloads.py` prepares RxNorm-derived fixtures when the necessary source files are supplied; it is not run automatically.

## Repository layout

- `cmd/medproof/`: command-line entry point
- `internal/circuit/`: ingredient and class circuit definitions and witnesses
- `internal/protocol/`: credential, signed-request, result-opening, replay, and receipt logic
- `internal/registry/`: circuit profile definitions and compilation
- `internal/workload/`: synthetic workloads and optional RxNorm workload loading
- `internal/bench/`: CPU benchmark runners and timing/RSS capture
- `configs/`: synthetic and RxNorm experiment manifests; these are configuration files, not bundled datasets
- `docs/`: prototype cryptographic profile

## Data, privacy, and licensing

Do not commit patient data, credentials, signing keys, API keys, generated experiment results, or licensed terminology archives. Use `.gitignore` and review the staged diff before publishing. The root project license has not been specified; see [`LICENSE_STATUS.md`](LICENSE_STATUS.md). Vendored Poseidon constants include their upstream MIT and Apache-2.0 notices in `internal/poseidon/`.

