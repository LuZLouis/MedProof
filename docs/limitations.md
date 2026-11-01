# Prototype limitations

- This repository implements a research prototype; it is not a clinical service and has not been validated for clinical use.
- The paper leaves some byte-level cryptographic parameters unspecified. The choices implemented here are recorded in `crypto_profile.md` and need independent cryptographic review.
- Key lifecycle, trust-policy integration, cross-language serialization vectors, and a complete signed audit/deployment path remain outside this prototype.
- The repository does not include RxNorm or other clinical data. Terminology matching, real LLM workloads, and clinical mapping accuracy are not established by this source release.
- Benchmarks require controlled hardware and a locally supplied workload dataset to reproduce any particular run. No measured experiment results are included in this source-only package.
