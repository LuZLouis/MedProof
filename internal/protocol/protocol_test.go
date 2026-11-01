package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"medproof/internal/poseidon"
	"medproof/internal/workload"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestCredentialCaptureAuditReplayAndTypedOpening(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	coordinatorPub, coordinatorPriv := keypair(t)
	recipientPub, recipientPriv := keypair(t)
	nu := TerminologyProfile{Release: "synthetic-fixture-v1", Normalization: "fixture-normalization-v1", MappingDigest: "fixture-digest"}
	meta := CredentialMetadata{SubjectBinding: "synthetic-subject", Snapshot: "snapshot-1", SourceScope: "reviewed-alerts", IssuedAt: "2026-10-28T00:00:00Z", ExpiresAt: "2026-10-29T00:00:00Z", EncodingProfile: "w16-b15"}
	credential, opening, err := IssueCredential([]uint16{9, 7, 7}, 16, "reviewed", nu, meta, "issuer-k1", issuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCredential(credential, issuerPub, "2026-10-28T01:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if len(opening.Codes) != 16 || opening.Codes[0] != 7 || opening.Codes[1] != 9 {
		t.Fatalf("credential normalization failed")
	}
	if _, _, err := IssueCredential(nil, 16, "unknown", nu, meta, "issuer-k1", issuerPriv); err == nil {
		t.Fatal("unknown review state accepted")
	}
	if _, _, err := IssueCredential(nil, 16, "nilknown", nu, meta, "issuer-k1", issuerPriv); err == nil {
		t.Fatal("unaffirmed nilknown accepted")
	}
	if _, _, err := IssueCredential(make([]uint16, 17), 16, "reviewed", nu, meta, "issuer-k1", issuerPriv); err == nil {
		t.Fatal("oversized alert set accepted")
	}

	capture := Capture{SchemaVersion: "candidate-array-v1", Candidates: []Candidate{{Kind: "concept", ConceptID: "RX1"}, {Kind: "concept", ConceptID: "missing"}, {Kind: "unresolved_text", Text: "unresolved"}, {Kind: "concept", ConceptID: "RX1"}}}
	raw, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest("session-1", credential.CA, meta.Snapshot, "parser-v1", "nonce-1", "auto", nu, Tier{Mode: "class", S: 16, TD: 4, Q: 2}, raw)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignRequest(request, "coord-k1", coordinatorPriv)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := workload.NewFixtureResolver(map[string][]uint16{"RX1": {7, 9}, "RX2": {8}})
	if err != nil {
		t.Fatal(err)
	}
	profiles := []RegisteredProfile{{Tier: Tier{Mode: "ingredient", S: 16, TU: 4, TM: 4}, Constraints: 100, ProfileHash: "i", VerificationKeyHash: "ivk", HasSetup: true}, {Tier: Tier{Mode: "class", S: 16, TD: 4, Q: 2}, Constraints: 80, ProfileHash: "c", VerificationKeyHash: "cvk", HasSetup: true}}
	nonces := &NonceStore{}
	audited, err := VerifySignedRequest(signed, coordinatorPub, credential, issuerPub, "2026-10-28T01:00:00Z", resolver, profiles, nonces)
	if err != nil {
		t.Fatal(err)
	}
	if audited.Profile.Tier.Mode != "class" || audited.Resolved.DistinctU != 2 || audited.Resolved.ReferencesL != 4 || audited.Resolved.ClassesH != 1 {
		t.Fatalf("unexpected audited public relation: %+v", audited.Resolved)
	}
	if audited.Resolved.Support[0] != 1 || audited.Resolved.Support[1] != 0 || audited.Resolved.Support[2] != 0 || audited.Resolved.Support[3] != 1 {
		t.Fatal("unsupported semantics changed")
	}
	if _, err := VerifySignedRequest(signed, coordinatorPub, credential, issuerPub, "2026-10-28T01:00:00Z", resolver, profiles, nonces); err == nil {
		t.Fatal("replayed nonce accepted")
	}

	rho := big.NewInt(1234)
	flags := []bool{true, false, false, true}
	cy, err := poseidon.CommitResult(audited.Digest, flags, rho)
	if err != nil {
		t.Fatal(err)
	}
	out, err := OpenResults(audited.Digest, flags, audited.Resolved.Support, rho.FillBytes(make([]byte, 32)), cy.String())
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != NoRecordedDirectMatch || out[1] != Unsupported || out[2] != Unsupported || out[3] != NoRecordedDirectMatch {
		t.Fatalf("unexpected typed results: %v", out)
	}
	classOut, err := OpenClassResults(audited.Digest, []bool{true}, audited.Resolved.ClassOf, audited.Resolved.Support, rho.FillBytes(make([]byte, 32)), cy.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(classOut) != 4 || classOut[2] != Unsupported {
		t.Fatalf("bad class expansion: %v", classOut)
	}
	if _, err := OpenResults(audited.Digest, []bool{true, true, false, true}, audited.Resolved.Support, rho.FillBytes(make([]byte, 32)), cy.String()); err == nil {
		t.Fatal("unsupported clearance accepted")
	}
	if _, err := OpenResults(audited.Digest, flags, audited.Resolved.Support, rho.FillBytes(make([]byte, 32)), "123"); err == nil {
		t.Fatal("tampered opening accepted")
	}

	receipt, err := SignReceipt(ReceiptUnsigned{RequestID: "batch-1", Digest: audited.Digest.String(), CY: cy.String(), Status: "received"}, "recipient-k1", recipientPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyReceipt(receipt, recipientPub) {
		t.Fatal("valid receipt rejected")
	}
	receipt.CY = "1"
	if VerifyReceipt(receipt, recipientPub) {
		t.Fatal("tampered receipt accepted")
	}
}

func TestSelectProfileFixedTieBreak(t *testing.T) {
	b := ResolvedBatch{DistinctU: 1, Support: []int{1}, ClassesH: 1, MaxQ: 1}
	profiles := []RegisteredProfile{
		{Tier: Tier{Mode: "class", S: 16, TD: 1, Q: 1}, Constraints: 10, HasSetup: true},
		{Tier: Tier{Mode: "ingredient", S: 16, TU: 1, TM: 1}, Constraints: 10, HasSetup: true},
	}
	selected, err := SelectProfile(b, profiles, 16)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Tier.Mode != "ingredient" {
		t.Fatalf("tie-break selected %s, want ingredient", selected.Tier.Mode)
	}
}

func TestCaptureAndProfileFailures(t *testing.T) {
	if _, err := ParseCapture([]byte(`{"schema_version":"v1","candidates":[{"kind":"concept","concept_id":"x"}],"extra":true}`)); err == nil {
		t.Fatal("unknown capture field accepted")
	}
	if _, err := ParseCapture([]byte(`{"schema_version":"v1","candidates":[{"kind":"unknown"}]}`)); err == nil {
		t.Fatal("unknown candidate kind accepted")
	}
	if _, err := ParseCapture([]byte(`{"schema_version":"v1","candidates":[]} {}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	r, err := workload.NewFixtureResolver(map[string][]uint16{"x": {1}})
	if err != nil {
		t.Fatal(err)
	}
	c := Capture{SchemaVersion: "v1", Candidates: []Candidate{{Kind: "concept", ConceptID: "x"}}}
	b, err := ResolveBatch(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SelectProfile(b, nil, 16); err == nil {
		t.Fatal("unregistered circuit selected")
	}
	if _, err := workload.NewFixtureResolver(map[string][]uint16{"bad": {0, 65535}}); err == nil {
		t.Fatal("invalid reserved fixture codes accepted")
	}
	if time.Now().Year() < 2026 {
		t.Fatal("unexpected system clock")
	}
}
