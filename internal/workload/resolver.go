package workload

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Resolver is a deterministic synthetic fixture adapter, not an RxNorm mapping.
type Resolver struct {
	Release       string              `json:"release"`
	Normalization string              `json:"normalization_policy"`
	Entries       map[string][]uint16 `json:"entries"`
	Digest        string              `json:"mapping_digest"`
}

func NewFixtureResolver(entries map[string][]uint16) (Resolver, error) {
	copyMap := make(map[string][]uint16, len(entries))
	keys := make([]string, 0, len(entries))
	for k, values := range entries {
		key := normalizeName(k)
		if key == "" || len(values) == 0 {
			return Resolver{}, errors.New("fixture requires named supported entries")
		}
		values = append([]uint16(nil), values...)
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		for i, v := range values {
			if v == 0 || v >= 65535 || (i > 0 && values[i-1] == v) {
				return Resolver{}, errors.New("fixture codes must be unique in [1,65534]")
			}
		}
		copyMap[key] = values
		keys = append(keys, key)
	}
	sort.Strings(keys)
	canonical := strings.Builder{}
	for _, k := range keys {
		canonical.WriteString(k)
		canonical.WriteByte(':')
		for _, v := range copyMap[k] {
			canonical.WriteString(strconv.Itoa(int(v)))
			canonical.WriteByte(',')
		}
		canonical.WriteByte('\n')
	}
	d := sha256.Sum256([]byte(canonical.String()))
	return Resolver{Release: "synthetic-fixture-v1", Normalization: "trim-space;unicode-lower;fixture-only", Entries: copyMap, Digest: hex.EncodeToString(d[:])}, nil
}

func (r Resolver) Resolve(name string) ([]uint16, bool) {
	v, ok := r.Entries[normalizeName(name)]
	return append([]uint16(nil), v...), ok
}

func normalizeName(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
