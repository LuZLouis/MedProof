package workload

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	jclinicalCommit = "b9333fb8f98a170499f1e0aa8555d02831c5eb36"
	jclinicalBlob   = "bf317abeefa9e66258d6e0e64d9ab0d99fa6b38a"
	jclinicalURL    = "https://raw.githubusercontent.com/seiji-shimizu/J-ClinicalBench-release/" + jclinicalCommit + "/data/benchmarks/CLR/MR/data.csv"
)

type JClinicalAudit struct {
	Commit            string  `json:"commit"`
	Blob              string  `json:"blob"`
	ReferenceLists    int     `json:"reference_lists"`
	MedicationNames   int     `json:"medication_name_entries"`
	DistinctNames     int     `json:"distinct_medication_names"`
	EmptyLists        int     `json:"empty_lists"`
	Over32            int     `json:"lists_over_32"`
	NonemptyWithin32  int     `json:"nonempty_within_32"`
	CountOnlyCoverage float64 `json:"count_only_coverage_nonempty"`
}

// FetchJClinicalAudit streams a pinned public CSV into memory, verifies its Git
// blob identity, and retains only aggregate counts. The source CSV is not saved.
func FetchJClinicalAudit(ctx context.Context, client *http.Client) (JClinicalAudit, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jclinicalURL, nil)
	if err != nil {
		return JClinicalAudit{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return JClinicalAudit{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return JClinicalAudit{}, fmt.Errorf("J-ClinicalBench download status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return JClinicalAudit{}, err
	}
	return ParseJClinicalCSV(body)
}

func ParseJClinicalCSV(body []byte) (JClinicalAudit, error) {
	gitBlob := sha1.Sum(append([]byte(fmt.Sprintf("blob %d\x00", len(body))), body...))
	blob := hex.EncodeToString(gitBlob[:])
	if blob != jclinicalBlob {
		return JClinicalAudit{}, fmt.Errorf("pinned Git blob mismatch: got %s", blob)
	}
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return JClinicalAudit{}, fmt.Errorf("parse pinned CSV: %w", err)
	}
	if len(rows) < 1 {
		return JClinicalAudit{}, fmt.Errorf("empty pinned CSV")
	}
	col := -1
	for i, name := range rows[0] {
		if strings.TrimSpace(name) == "medications" {
			col = i
			break
		}
	}
	if col < 0 {
		return JClinicalAudit{}, fmt.Errorf("CSV lacks medications column")
	}
	a := JClinicalAudit{Commit: jclinicalCommit, Blob: blob}
	unique := map[string]struct{}{}
	for rowIndex, row := range rows[1:] {
		if col >= len(row) {
			return JClinicalAudit{}, fmt.Errorf("row %d lacks medications field", rowIndex+2)
		}
		encoded := strings.TrimSpace(row[col])
		names, err := parseMedicationNames(encoded)
		if err != nil {
			return JClinicalAudit{}, fmt.Errorf("row %d medication list: %w", rowIndex+2, err)
		}
		// The CSV encodes six empty medication lists as a one-element list
		// containing an empty string. Treat that placeholder as no medication.
		filtered := names[:0]
		for _, name := range names {
			if strings.TrimSpace(name) != "" {
				filtered = append(filtered, strings.TrimSpace(name))
			}
		}
		names = filtered
		a.ReferenceLists++
		if len(names) == 0 {
			a.EmptyLists++
			continue
		}
		if len(names) > 32 {
			a.Over32++
		} else {
			a.NonemptyWithin32++
		}
		a.MedicationNames += len(names)
		for _, name := range names {
			unique[name] = struct{}{}
		}
	}
	a.DistinctNames = len(unique)
	if a.ReferenceLists > a.EmptyLists {
		a.CountOnlyCoverage = float64(a.NonemptyWithin32) / float64(a.ReferenceLists-a.EmptyLists)
	}
	if a.ReferenceLists != 124 || a.MedicationNames != 1215 || a.DistinctNames != 310 || a.EmptyLists != 6 || a.Over32 != 6 || a.NonemptyWithin32 != 112 {
		return a, fmt.Errorf("pinned count assertion failed: lists=%d names=%d distinct=%d empty=%d over32=%d nonemptyWithin32=%d", a.ReferenceLists, a.MedicationNames, a.DistinctNames, a.EmptyLists, a.Over32, a.NonemptyWithin32)
	}
	return a, nil
}

// The pinned source serializes this column as a Python-style list of single
// quoted strings, rather than JSON. Parse only that restricted literal form.
func parseMedicationNames(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" || s == "[]" {
		return nil, nil
	}
	var jsonNames []string
	if json.Unmarshal([]byte(s), &jsonNames) == nil {
		return jsonNames, nil
	}
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return nil, fmt.Errorf("expected a list")
	}
	i := 1
	skip := func() {
		for i < len(s)-1 && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
			i++
		}
	}
	var names []string
	skip()
	for i < len(s)-1 {
		if s[i] != '\'' && s[i] != '"' {
			return nil, fmt.Errorf("expected quoted list item")
		}
		quote, start := s[i], i
		i++
		for i < len(s)-1 {
			if s[i] == '\\' {
				i += 2
				continue
			}
			if s[i] == quote {
				i++
				break
			}
			i++
		}
		if i > len(s)-1 || s[i-1] != quote {
			return nil, fmt.Errorf("unterminated list item")
		}
		literal := s[start+1 : i-1]
		var value strings.Builder
		for k := 0; k < len(literal); k++ {
			if literal[k] == '\\' && k+1 < len(literal) {
				k++
				switch literal[k] {
				case 'n':
					value.WriteByte('\n')
				case 'r':
					value.WriteByte('\r')
				case 't':
					value.WriteByte('\t')
				default:
					value.WriteByte(literal[k])
				}
			} else {
				value.WriteByte(literal[k])
			}
		}
		names = append(names, value.String())
		skip()
		if i == len(s)-1 {
			break
		}
		if s[i] != ',' {
			return nil, fmt.Errorf("expected comma")
		}
		i++
		skip()
	}
	return names, nil
}
