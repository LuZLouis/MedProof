# Cryptographic profile v1 — frozen for prototype smoke tests

Status: **prototype profile implemented and exercised in small Groth16 smoke tests**. It is an engineering refinement because V13 does not specify byte-level parameters. Independent review is required before clinical use or paper claims.

## Fixed by the paper

- Proof system: Groth16 over BN254, CPU-only.
- Alert code width `w=16`, pack width `b=15` at the baseline; each packed word contains 240 bits.
- Real alert codes are in `[1, 2^w-2]`; private zero padding is `0`; public ingredient padding is `2^w-1`.
- `C_A` and `C_Y` use randomized, domain-separated Poseidon commitments. `C_Y` binds the request digest and packed result bits.
- Request digest domain tag in the paper: `MedProof/req/v12`.

## Frozen prototype parameters

- Toolchain: Go `1.26.10`; `github.com/consensys/gnark v0.16.4`; gnark-crypto `v0.21.1-0.20260913224755-1409fe592052`; `github.com/iden3/go-iden3-crypto/v2 v2.0.0`.
- Poseidon parameters: Circom-compatible BN254 scalar-field tables from iden3 v2.0.0 `poseidon/constants.go`, vendored with its Apache-2.0/MIT licenses. `N_F=8`; `N_P` by width `t=2..17` is `{56,57,56,60,60,63,64,63,60,66,60,65,70,60,64,68}`. The gadget mirrors upstream `HashWithStateEx`; S-box exponent is 5. Native and circuit implementations pass the upstream `[1,2] -> 7853200120776062878684798364095072458815029376092732009249414926327459813530` vector.
- State width is `t=input_count+1`; state[0] is the initial domain element and inputs occupy state[1..]. `C_A` hashes `ceil(S/15)` packed words followed by `rho_A`. `C_Y` hashes `[d_q, BitPack(result), rho_Y]`. Each compiled shape therefore pins its arity and Poseidon parameter table.
- Domain elements are the big-endian integer encodings of ASCII `MedProof/commit/A` and `MedProof/commit/Y`. Codes use little-endian positions within packed words (`a_j * 2^(16*j)`), up to 15 codes per 240-bit word. Output bit `j` has weight `2^j`.
- Canonical request bytes are UTF-8 JSON of a typed struct in declared field order, using `encoding/json` without HTML escaping or trailing newline; byte slices use Go's base64 JSON encoding. Request field digest is `OS2IP_BE(SHA256("MedProof/req/v12" || 0x00 || uint64_be(len(JSON)) || JSON)) mod r`, with `r` the BN254 scalar modulus. This digest is supplied as a public input and constrained through `C_Y`.
- Openings use uniform canonical scalar field samples from `crypto/rand.Int(r)` and 32-byte big-endian serialization when persisted or signed.
- Prototype signatures use Ed25519. Domain prefixes are `MedProof/issuer/v1\x00`, `MedProof/coordinator/v1\x00`, and `MedProof/receipt/v1\x00`, followed by an 8-byte big-endian length and canonical JSON.

## Remaining assurance work

- Key epoch/rotation and certificate policy.
- Cross-language serialization vectors for alert/result commitments, request digest, signatures, and receipts.
- Independent review of the selected Poseidon parameters, hiding assumptions, and randomized opening handling.
- Full protocol tests and a full circuit-profile registry; current tested profile shapes are small smoke shapes only.

## Gate

Do not change parameters without a version bump and regenerated vectors. These settings are not a clinical deployment profile. This source-only repository contains no experiment result files; consult a separately distributed, reviewed data package for any benchmark evidence.
