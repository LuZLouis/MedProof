package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"medproof/internal/poseidon"
)

const (
	IssuerPrefix      = "MedProof/issuer/v1\x00"
	CoordinatorPrefix = "MedProof/coordinator/v1\x00"
	ReceiptPrefix     = "MedProof/receipt/v1\x00"
	RequestDomain     = "MedProof/req/v12"
)

type TerminologyProfile struct {
	Release       string `json:"release"`
	Normalization string `json:"normalization_policy"`
	MappingDigest string `json:"mapping_digest"`
}
type CredentialMetadata struct {
	SubjectBinding   string `json:"subject_binding"`
	Snapshot         string `json:"snapshot"`
	SourceScope      string `json:"source_scope"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	EncodingProfile  string `json:"encoding_profile"`
	NilKnownAffirmed bool   `json:"nilknown_affirmed"`
}
type CredentialUnsigned struct {
	CA          string             `json:"C_A"`
	Nu          TerminologyProfile `json:"nu"`
	Metadata    CredentialMetadata `json:"metadata"`
	ReviewState string             `json:"review_state"`
	Capacity    int                `json:"S"`
	Width       int                `json:"w"`
	Pack        int                `json:"b"`
}
type Credential struct {
	CredentialUnsigned
	IssuerKeyID string `json:"issuer_key_id"`
	Signature   []byte `json:"signature"`
}
type credentialSignedPayload struct {
	CredentialUnsigned CredentialUnsigned `json:"credential"`
	IssuerKeyID        string             `json:"issuer_key_id"`
}
type AlertOpening struct {
	Codes []uint16 `json:"codes"`
	Rho   []byte   `json:"rho"`
}

func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

func signedMessage(prefix string, payload []byte) []byte {
	b := make([]byte, 0, len(prefix)+8+len(payload))
	b = append(b, []byte(prefix)...)
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(payload)))
	b = append(b, size[:]...)
	return append(b, payload...)
}

func signJSON(prefix string, value any, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	payload, err := canonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, signedMessage(prefix, payload)), nil
}

func verifyJSON(prefix string, value any, signature []byte, key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	payload, err := canonicalJSON(value)
	return err == nil && ed25519.Verify(key, signedMessage(prefix, payload), signature)
}

func parseReviewState(v string) bool { return v == "reviewed" || v == "nilknown" }

func IssueCredential(codes []uint16, capacity int, reviewState string, nu TerminologyProfile, meta CredentialMetadata, issuerID string, issuerKey ed25519.PrivateKey) (Credential, AlertOpening, error) {
	if !parseReviewState(reviewState) {
		return Credential{}, AlertOpening{}, errors.New("review state is not eligible for screening")
	}
	if reviewState == "nilknown" && !meta.NilKnownAffirmed {
		return Credential{}, AlertOpening{}, errors.New("nilknown requires an affirmative reviewed assertion")
	}
	if nu.Release == "" || nu.Normalization == "" || nu.MappingDigest == "" || meta.Snapshot == "" || meta.ExpiresAt == "" || meta.SourceScope == "" || issuerID == "" {
		return Credential{}, AlertOpening{}, errors.New("credential scope/profile incomplete")
	}
	rho, err := poseidon.RandomOpening()
	if err != nil {
		return Credential{}, AlertOpening{}, err
	}
	ca, padded, err := poseidon.CommitAlert(codes, capacity, rho)
	if err != nil {
		return Credential{}, AlertOpening{}, err
	}
	unsigned := CredentialUnsigned{CA: ca.String(), Nu: nu, Metadata: meta, ReviewState: reviewState, Capacity: capacity, Width: 16, Pack: 15}
	sig, err := signJSON(IssuerPrefix, credentialSignedPayload{CredentialUnsigned: unsigned, IssuerKeyID: issuerID}, issuerKey)
	if err != nil {
		return Credential{}, AlertOpening{}, err
	}
	return Credential{CredentialUnsigned: unsigned, IssuerKeyID: issuerID, Signature: sig}, AlertOpening{Codes: padded, Rho: rho.FillBytes(make([]byte, 32))}, nil
}

func VerifyCredential(credential Credential, issuerKey ed25519.PublicKey, now string) error {
	if !parseReviewState(credential.ReviewState) {
		return errors.New("credential review state is ineligible")
	}
	nowTime, nowErr := time.Parse(time.RFC3339, now)
	expires, expiresErr := time.Parse(time.RFC3339, credential.Metadata.ExpiresAt)
	issued, issuedErr := time.Parse(time.RFC3339, credential.Metadata.IssuedAt)
	if nowErr != nil || expiresErr != nil || issuedErr != nil || !issued.Before(expires) {
		return errors.New("credential lifetime is malformed")
	}
	if nowTime.Before(issued) || !nowTime.Before(expires) {
		return errors.New("credential expired")
	}
	if !verifyJSON(IssuerPrefix, credentialSignedPayload{CredentialUnsigned: credential.CredentialUnsigned, IssuerKeyID: credential.IssuerKeyID}, credential.Signature, issuerKey) {
		return errors.New("issuer signature invalid")
	}
	return nil
}

type Candidate struct {
	Kind      string `json:"kind"`
	ConceptID string `json:"concept_id,omitempty"`
	Text      string `json:"text,omitempty"`
}
type Capture struct {
	SchemaVersion string      `json:"schema_version"`
	Candidates    []Candidate `json:"candidates"`
}
type Tier struct {
	Mode string `json:"mode"`
	S    int    `json:"S"`
	TU   int    `json:"t_u,omitempty"`
	TM   int    `json:"t_m,omitempty"`
	TD   int    `json:"t_d,omitempty"`
	Q    int    `json:"q,omitempty"`
}
type Request struct {
	SessionID        string             `json:"session_id"`
	CA               string             `json:"C_A"`
	Nu               TerminologyProfile `json:"nu"`
	Snapshot         string             `json:"snapshot"`
	RawCapture       []byte             `json:"raw_capture"`
	RawCaptureDigest string             `json:"raw_capture_digest"`
	ParserVersion    string             `json:"parser_version"`
	Nonce            string             `json:"nonce"`
	RequestedMode    string             `json:"requested_mode"`
	Tier             Tier               `json:"tier"`
}
type SignedRequest struct {
	Request          Request `json:"request"`
	CoordinatorKeyID string  `json:"coordinator_key_id"`
	Signature        []byte  `json:"signature"`
}
type requestSignedPayload struct {
	Request          Request `json:"request"`
	CoordinatorKeyID string  `json:"coordinator_key_id"`
}

func NewRequest(sessionID, ca, snapshot, parserVersion, nonce, requestedMode string, nu TerminologyProfile, tier Tier, rawCapture []byte) (Request, error) {
	if len(rawCapture) == 0 {
		return Request{}, errors.New("empty structured capture")
	}
	h := sha256.Sum256(rawCapture)
	return Request{SessionID: sessionID, CA: ca, Nu: nu, Snapshot: snapshot, RawCapture: append([]byte(nil), rawCapture...), RawCaptureDigest: fmt.Sprintf("%x", h[:]), ParserVersion: parserVersion, Nonce: nonce, RequestedMode: requestedMode, Tier: tier}, nil
}

func SignRequest(r Request, coordinatorID string, key ed25519.PrivateKey) (SignedRequest, error) {
	if coordinatorID == "" {
		return SignedRequest{}, errors.New("coordinator key ID required")
	}
	sig, err := signJSON(CoordinatorPrefix, requestSignedPayload{Request: r, CoordinatorKeyID: coordinatorID}, key)
	return SignedRequest{Request: r, CoordinatorKeyID: coordinatorID, Signature: sig}, err
}

// VerifyRequestSignature validates the coordinator's signature over the full
// typed request. Scope, capture, nonce, and profile checks are performed by
// VerifySignedRequest after this cryptographic check.
func VerifyRequestSignature(signed SignedRequest, coordinatorKey ed25519.PublicKey) bool {
	return signed.CoordinatorKeyID != "" && verifyJSON(CoordinatorPrefix, requestSignedPayload{Request: signed.Request, CoordinatorKeyID: signed.CoordinatorKeyID}, signed.Signature, coordinatorKey)
}

func RequestDigest(r Request) (*big.Int, error) {
	canonical, err := canonicalJSON(r)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(RequestDomain))
	h.Write([]byte{0})
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(canonical)))
	h.Write(n[:])
	h.Write(canonical)
	d := new(big.Int).SetBytes(h.Sum(nil))
	return d.Mod(d, fr.Modulus()), nil
}

func ParseCapture(raw []byte) (Capture, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Capture
	if err := dec.Decode(&c); err != nil {
		return Capture{}, fmt.Errorf("capture parse failed: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Capture{}, errors.New("capture has trailing JSON data")
	}
	if c.SchemaVersion == "" || c.Candidates == nil {
		return Capture{}, errors.New("capture missing schema version or complete candidate array")
	}
	for i, p := range c.Candidates {
		switch p.Kind {
		case "concept":
			if strings.TrimSpace(p.ConceptID) == "" || p.Text != "" {
				return Capture{}, fmt.Errorf("candidate %d malformed concept", i)
			}
		case "unresolved_text":
			if strings.TrimSpace(p.Text) == "" || p.ConceptID != "" {
				return Capture{}, fmt.Errorf("candidate %d malformed unresolved entry", i)
			}
		default:
			return Capture{}, fmt.Errorf("candidate %d has unknown type", i)
		}
	}
	return c, nil
}

type Resolver interface {
	Resolve(conceptID string) ([]uint16, bool)
}
type ResolvedBatch struct {
	Ingredients                            []uint16
	Incidence                              [][]int
	Support                                []int
	ClassIngredients                       [][]uint16
	ClassOf                                []int
	DistinctU, ReferencesL, ClassesH, MaxQ int
}

func ResolveBatch(capture Capture, resolver Resolver) (ResolvedBatch, error) {
	if len(capture.Candidates) == 0 {
		return ResolvedBatch{}, errors.New("empty candidate array")
	}
	result := ResolvedBatch{Support: make([]int, len(capture.Candidates)), Incidence: make([][]int, len(capture.Candidates)), ClassOf: make([]int, len(capture.Candidates))}
	sets := make([][]uint16, len(capture.Candidates))
	ingredientSet := map[uint16]bool{}
	classIndex := map[string]int{}
	for j, p := range capture.Candidates {
		if p.Kind != "concept" {
			result.ClassOf[j] = -1
			continue
		}
		ids, ok := resolver.Resolve(p.ConceptID)
		if !ok || len(ids) == 0 {
			result.ClassOf[j] = -1
			continue
		}
		ids = append([]uint16(nil), ids...)
		sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
		for i, id := range ids {
			if id == 0 || id == 65535 || (i > 0 && ids[i-1] == id) {
				return ResolvedBatch{}, errors.New("resolver returned invalid/nonunique ingredient code")
			}
			ingredientSet[id] = true
		}
		sets[j] = ids
		result.Support[j] = 1
		result.ReferencesL += len(ids)
		if len(ids) > result.MaxQ {
			result.MaxQ = len(ids)
		}
		key := fmt.Sprint(ids)
		cls, exists := classIndex[key]
		if !exists {
			cls = len(classIndex)
			classIndex[key] = cls
			result.ClassIngredients = append(result.ClassIngredients, ids)
		}
		result.ClassOf[j] = cls
	}
	if result.ReferencesL == 0 {
		return ResolvedBatch{}, errors.New("no supported candidates: fail closed")
	}
	for id := range ingredientSet {
		result.Ingredients = append(result.Ingredients, id)
	}
	sort.Slice(result.Ingredients, func(i, j int) bool { return result.Ingredients[i] < result.Ingredients[j] })
	result.DistinctU = len(result.Ingredients)
	result.ClassesH = len(result.ClassIngredients)
	for j, ids := range sets {
		result.Incidence[j] = make([]int, result.DistinctU)
		for _, id := range ids {
			i := sort.Search(len(result.Ingredients), func(i int) bool { return result.Ingredients[i] >= id })
			result.Incidence[j][i] = 1
		}
	}
	return result, nil
}

type RegisteredProfile struct {
	Tier                Tier
	Constraints         int
	ProfileHash         string
	VerificationKeyHash string
	HasSetup            bool
}

func SelectProfile(batch ResolvedBatch, profiles []RegisteredProfile, S int) (RegisteredProfile, error) {
	var candidates []RegisteredProfile
	for _, p := range profiles {
		if !p.HasSetup || p.Tier.S != S {
			continue
		}
		if p.Tier.Mode == "ingredient" && p.Tier.TU >= batch.DistinctU && p.Tier.TM >= len(batch.Support) {
			candidates = append(candidates, p)
		}
		if p.Tier.Mode == "class" && p.Tier.TD >= batch.ClassesH && p.Tier.Q >= batch.MaxQ {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return RegisteredProfile{}, errors.New("no feasible registered circuit; fail closed")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Constraints != candidates[j].Constraints {
			return candidates[i].Constraints < candidates[j].Constraints
		}
		if candidates[i].Tier.Mode != candidates[j].Tier.Mode {
			// Stable protocol tie-break: ingredient precedes class, independent
			// of lexical mode names or registry insertion order.
			return candidates[i].Tier.Mode == "ingredient"
		}
		if candidates[i].Tier.TU != candidates[j].Tier.TU {
			return candidates[i].Tier.TU < candidates[j].Tier.TU
		}
		if candidates[i].Tier.TM != candidates[j].Tier.TM {
			return candidates[i].Tier.TM < candidates[j].Tier.TM
		}
		if candidates[i].Tier.TD != candidates[j].Tier.TD {
			return candidates[i].Tier.TD < candidates[j].Tier.TD
		}
		return candidates[i].Tier.Q < candidates[j].Tier.Q
	})
	return candidates[0], nil
}

type AuditedRequest struct {
	Digest   *big.Int
	Capture  Capture
	Resolved ResolvedBatch
	Profile  RegisteredProfile
}

// VerifySignedRequest authenticates the complete captured structured array,
// independently rebuilds public mappings, checks canonical profile dispatch,
// and reserves the nonce before the caller performs Groth16 verification.
func VerifySignedRequest(signed SignedRequest, coordinatorKey ed25519.PublicKey, credential Credential, issuerKey ed25519.PublicKey, now string, resolver Resolver, profiles []RegisteredProfile, nonces *NonceStore) (AuditedRequest, error) {
	r := signed.Request
	if signed.CoordinatorKeyID == "" || !verifyJSON(CoordinatorPrefix, requestSignedPayload{Request: r, CoordinatorKeyID: signed.CoordinatorKeyID}, signed.Signature, coordinatorKey) {
		return AuditedRequest{}, errors.New("coordinator signature invalid")
	}
	if err := VerifyCredential(credential, issuerKey, now); err != nil {
		return AuditedRequest{}, err
	}
	if r.CA != credential.CA || r.Nu != credential.Nu || r.Snapshot != credential.Metadata.Snapshot {
		return AuditedRequest{}, errors.New("request credential scope/profile mismatch")
	}
	rawDigest := sha256.Sum256(r.RawCapture)
	if fmt.Sprintf("%x", rawDigest[:]) != r.RawCaptureDigest {
		return AuditedRequest{}, errors.New("raw structured capture digest mismatch")
	}
	capture, err := ParseCapture(r.RawCapture)
	if err != nil {
		return AuditedRequest{}, err
	}
	resolved, err := ResolveBatch(capture, resolver)
	if err != nil {
		return AuditedRequest{}, err
	}
	profile, err := SelectProfile(resolved, profiles, credential.Capacity)
	if err != nil {
		return AuditedRequest{}, err
	}
	if (r.RequestedMode != "auto" && r.RequestedMode != profile.Tier.Mode) || r.Tier != profile.Tier {
		return AuditedRequest{}, errors.New("noncanonical mode/tier selection")
	}
	digest, err := RequestDigest(r)
	if err != nil {
		return AuditedRequest{}, err
	}
	if nonces == nil {
		return AuditedRequest{}, errors.New("nonce replay store unavailable")
	}
	if r.SessionID == "" || r.Nonce == "" {
		return AuditedRequest{}, errors.New("session ID and fresh nonce required")
	}
	if err := nonces.Reserve(r.SessionID, r.Nonce); err != nil {
		return AuditedRequest{}, err
	}
	return AuditedRequest{Digest: digest, Capture: capture, Resolved: resolved, Profile: profile}, nil
}

type NonceStore struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (n *NonceStore) Reserve(session, nonce string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = map[string]bool{}
	}
	key := session + "\x00" + nonce
	if n.seen[key] {
		return errors.New("nonce replay")
	}
	n.seen[key] = true
	return nil
}

type ReceiptUnsigned struct {
	RequestID string `json:"request_id"`
	Digest    string `json:"d_q"`
	CY        string `json:"C_Y"`
	Status    string `json:"status"`
}
type Receipt struct {
	ReceiptUnsigned
	RecipientKeyID string `json:"recipient_key_id"`
	Signature      []byte `json:"signature"`
}
type receiptSignedPayload struct {
	ReceiptUnsigned ReceiptUnsigned `json:"receipt"`
	RecipientKeyID  string          `json:"recipient_key_id"`
}

func SignReceipt(r ReceiptUnsigned, recipientID string, key ed25519.PrivateKey) (Receipt, error) {
	if r.Status != "received" || r.RequestID == "" || recipientID == "" {
		return Receipt{}, errors.New("invalid receipt fields")
	}
	sig, err := signJSON(ReceiptPrefix, receiptSignedPayload{ReceiptUnsigned: r, RecipientKeyID: recipientID}, key)
	return Receipt{ReceiptUnsigned: r, RecipientKeyID: recipientID, Signature: sig}, err
}
func VerifyReceipt(r Receipt, key ed25519.PublicKey) bool {
	return verifyJSON(ReceiptPrefix, receiptSignedPayload{ReceiptUnsigned: r.ReceiptUnsigned, RecipientKeyID: r.RecipientKeyID}, r.Signature, key)
}

type Outcome string

const (
	DirectAlert           Outcome = "DirectAlert"
	NoRecordedDirectMatch Outcome = "NoRecordedDirectMatch"
	Unsupported           Outcome = "Unsupported"
)

// OpenResults runs at the authorized recipient. The auditor receives neither
// the opening nor the typed outcomes.
func OpenResults(digest *big.Int, flags []bool, support []int, rhoBytes []byte, commitment string) ([]Outcome, error) {
	if len(flags) == 0 || len(flags) != len(support) || len(rhoBytes) != 32 {
		return nil, errors.New("invalid result opening shape")
	}
	rho := new(big.Int).SetBytes(rhoBytes)
	if rho.Cmp(fr.Modulus()) >= 0 {
		return nil, errors.New("noncanonical result randomness")
	}
	for j, s := range support {
		if s != 0 && s != 1 {
			return nil, errors.New("support mask is not boolean")
		}
		if s == 0 && flags[j] {
			return nil, errors.New("unsupported position cannot carry a clearance flag")
		}
	}
	cy, err := poseidon.CommitResult(digest, flags, rho)
	if err != nil {
		return nil, err
	}
	want, ok := new(big.Int).SetString(commitment, 10)
	if !ok || want.Cmp(cy) != 0 {
		return nil, errors.New("result opening does not match commitment")
	}
	out := make([]Outcome, len(flags))
	for j, s := range support {
		if s == 0 {
			out[j] = Unsupported
		} else if flags[j] {
			out[j] = NoRecordedDirectMatch
		} else {
			out[j] = DirectAlert
		}
	}
	return out, nil
}

func OpenClassResults(digest *big.Int, classFlags []bool, classOf, support []int, rhoBytes []byte, commitment string) ([]Outcome, error) {
	if len(classOf) != len(support) {
		return nil, errors.New("class map/support shape mismatch")
	}
	flags := make([]bool, len(classOf))
	for j, cls := range classOf {
		if support[j] == 0 {
			continue
		}
		if cls < 0 || cls >= len(classFlags) {
			return nil, errors.New("invalid public class expansion map")
		}
		flags[j] = classFlags[cls]
	}
	return OpenResults(digest, flags, support, rhoBytes, commitment)
}
