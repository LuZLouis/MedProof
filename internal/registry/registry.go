package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"medproof/internal/circuit"
)

type Profile struct {
	Mode string `json:"mode"`
	S    int    `json:"S"`
	TU   int    `json:"t_u,omitempty"`
	TM   int    `json:"t_m,omitempty"`
	TD   int    `json:"t_d,omitempty"`
	Q    int    `json:"q,omitempty"`
}
type Entry struct {
	Profile              Profile `json:"profile"`
	ProfileHash          string  `json:"profile_hash"`
	ConstraintCount      int     `json:"constraint_count"`
	SetupKeyHash         string  `json:"setup_key_hash"`
	VerificationKeyHash  string  `json:"verification_key_hash"`
	ProvingKeyBytes      int64   `json:"proving_key_bytes"`
	VerificationKeyBytes int64   `json:"verification_key_bytes"`
	CompileMS            int64   `json:"compile_ms"`
	SetupMS              int64   `json:"setup_ms"`
	Backend              string  `json:"backend"`
	Curve                string  `json:"curve"`
	GnarkVersion         string  `json:"gnark_version"`
	GnarkCryptoVersion   string  `json:"gnark_crypto_version"`
	CreatedAt            string  `json:"created_at"`
	HasSetup             bool    `json:"has_setup"`
}
type Registry struct {
	Version string  `json:"version"`
	Entries []Entry `json:"entries"`
}

func HashProfile(p Profile) (string, error) {
	b, e := json.Marshal(p)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(append([]byte("MedProof/profile/v1\x00"), b...))
	return hex.EncodeToString(h[:]), nil
}

func Compile(p Profile) (frontend.Circuit, error) {
	switch p.Mode {
	case "ingredient":
		if p.TU < 1 || p.TM < 1 || p.TD != 0 || p.Q != 0 {
			return nil, errors.New("invalid ingredient profile dimensions")
		}
		return circuit.NewIngredientTemplate(p.S, p.TU, p.TM)
	case "class":
		if p.TD < 1 || p.Q < 1 || p.TU != 0 || p.TM != 0 {
			return nil, errors.New("invalid class profile dimensions")
		}
		return circuit.NewClassTemplate(p.S, p.TD, p.Q)
	default:
		return nil, fmt.Errorf("unknown proof mode %q", p.Mode)
	}
}

func SetupProfile(p Profile, keyRoot string) (Entry, error) {
	profileHash, err := HashProfile(p)
	if err != nil {
		return Entry{}, err
	}
	template, err := Compile(p)
	if err != nil {
		return Entry{}, err
	}
	start := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, template)
	if err != nil {
		return Entry{}, err
	}
	compileMS := time.Since(start).Milliseconds()
	start = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return Entry{}, err
	}
	setupMS := time.Since(start).Milliseconds()
	dir := filepath.Join(keyRoot, profileHash)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return Entry{}, err
	}
	pkBytes, pkHash, err := writeHash(filepath.Join(dir, "proving.key"), pk)
	if err != nil {
		return Entry{}, err
	}
	vkBytes, vkHash, err := writeHash(filepath.Join(dir, "verifying.key"), vk)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Profile: p, ProfileHash: profileHash, ConstraintCount: ccs.GetNbConstraints(), SetupKeyHash: pkHash, VerificationKeyHash: vkHash, ProvingKeyBytes: pkBytes, VerificationKeyBytes: vkBytes, CompileMS: compileMS, SetupMS: setupMS, Backend: "Groth16", Curve: "BN254", GnarkVersion: "v0.16.4", GnarkCryptoVersion: "v0.21.1-0.20260913224755-1409fe592052", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), HasSetup: true}, nil
}

type writerTo interface {
	WriteTo(io.Writer) (int64, error)
}

func writeHash(path string, value writerTo) (int64, string, error) {
	file, err := os.Create(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	h := sha256.New()
	w := io.MultiWriter(file, h)
	n, err := value.WriteTo(w)
	if err != nil {
		return 0, "", err
	}
	if err = file.Sync(); err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func Save(path string, r Registry) error {
	sort.Slice(r.Entries, func(i, j int) bool { return r.Entries[i].ProfileHash < r.Entries[j].ProfileHash })
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Load(path string) (Registry, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Registry{}, e
	}
	var r Registry
	e = json.Unmarshal(b, &r)
	return r, e
}
