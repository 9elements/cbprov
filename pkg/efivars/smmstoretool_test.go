package efivars

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Differential tests against coreboot's util/smmstoretool. Build it out of
// tree and run:
//
//	CBPROV_SMMSTORETOOL=/path/to/smmstoretool go test ./pkg/efivars/ -run Smmstoretool
//
// smmstoretool always rewrites the store compacted, so byte equality is only
// expected for fresh stores; otherwise the tests compare what each side reads.

func smmstoretool(t *testing.T) func(args ...string) []byte {
	t.Helper()
	bin := os.Getenv("CBPROV_SMMSTORETOOL")
	if bin == "" {
		t.Skip("CBPROV_SMMSTORETOOL not set")
	}
	return func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(bin, args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("smmstoretool %v: %v\n%s", args, err, stderr.String())
		}
		return out
	}
}

// toolGUID formats g the way smmstoretool parses it (no dash in the last part).
func toolGUID(g GUID) string {
	s := g.String()
	return s[:23] + s[24:]
}

func writeFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func toolSet(t *testing.T, run func(...string) []byte, file string, g GUID, name string, data []byte) {
	t.Helper()
	run(file, "set", "-g", toolGUID(g), "-n", name, "-t", "file", "-v", writeFile(t, "data", data))
}

// maskPubKeyIndex clears PubKeyIndex, the one header field where smmstoretool
// (0xffffffff) and EDK2/cbprov (0) differ for new records.
func maskPubKeyIndex(t *testing.T, b []byte) []byte {
	t.Helper()
	b = bytes.Clone(b)
	for _, r := range mustParse(t, b).recs {
		copy(b[r.off+32:r.off+36], []byte{0, 0, 0, 0})
	}
	return b
}

type toolVar struct {
	g    GUID
	name string
	data []byte
}

var toolVars = []toolVar{
	{CorebootNvDataGUID, "power_on_after_fail", u32(1)},
	{efiGlobalGUID, "Timeout", []byte{5, 0}},
	{CorebootNvDataGUID, "debug_level", u32(7)},
	{imageSecGUID, "blob", bytes.Repeat([]byte{0x11, 0x22, 0x33}, 99)},
}

func TestSmmstoretoolFormatsLikeUs(t *testing.T) {
	run := smmstoretool(t)
	file := writeFile(t, "store.bin", bytes.Repeat([]byte{0xff}, 0x40000))
	toolSet(t, run, file, CorebootNvDataGUID, "a", u32(1))
	got := readFile(t, file)

	want := mustFormat(t, 0x40000, 0x10000)
	if !bytes.Equal(got[:0x64], want[:0x64]) {
		t.Fatalf("headers differ:\n tool %x\n ours %x", got[:0x64], want[:0x64])
	}
	s := mustParse(t, want)
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	if !bytes.Equal(maskPubKeyIndex(t, got), maskPubKeyIndex(t, s.Bytes())) {
		t.Fatal("stores differ")
	}
}

func TestSmmstoretoolFreshSetsByteEqual(t *testing.T) {
	run := smmstoretool(t)
	base := mustFormat(t, 0x80000, 0x10000)
	file := writeFile(t, "store.bin", base)
	s := mustParse(t, base)
	for _, v := range toolVars {
		toolSet(t, run, file, v.g, v.name, v.data)
		mustSet(t, s, v.g, v.name, v.data)
	}
	if !bytes.Equal(maskPubKeyIndex(t, readFile(t, file)), maskPubKeyIndex(t, s.Bytes())) {
		t.Fatal("stores differ")
	}
}

func TestSmmstoretoolReadsOurs(t *testing.T) {
	run := smmstoretool(t)
	s := mustParse(t, appendRaw(t, mustFormat(t, 0x80000, 0x10000),
		foreignRecord(t, efiGlobalGUID, "Boot0000", 7, []byte("boot option"))))
	for _, v := range toolVars {
		mustSet(t, s, v.g, v.name, v.data)
	}
	mustSet(t, s, CorebootNvDataGUID, "debug_level", u32(8))
	if _, err := s.Delete(efiGlobalGUID, "Timeout"); err != nil {
		t.Fatal(err)
	}
	file := writeFile(t, "store.bin", s.Bytes())

	vars := s.Variables()
	list := strings.Split(strings.TrimSpace(string(run(file, "list"))), "\n")
	if len(list) != len(vars) {
		t.Fatalf("smmstoretool lists %d variables, we have %d:\n%s", len(list), len(vars), strings.Join(list, "\n"))
	}
	for _, v := range vars {
		if got := run(file, "get", "-g", toolGUID(v.GUID), "-n", v.Name, "-t", "raw"); !bytes.Equal(got, v.Data) {
			t.Errorf("%s: smmstoretool reads %x, want %x", v.Name, got, v.Data)
		}
	}
}

func TestSmmstoretoolWritesWeRead(t *testing.T) {
	run := smmstoretool(t)
	s := mustParse(t, mustFormat(t, 0x80000, 0x10000))
	for _, v := range toolVars {
		mustSet(t, s, v.g, v.name, v.data)
	}
	mustSet(t, s, CorebootNvDataGUID, "debug_level", u32(8)) // leaves a deleted record
	file := writeFile(t, "store.bin", s.Bytes())

	toolSet(t, run, file, CorebootNvDataGUID, "power_on_after_fail", u32(0))
	toolSet(t, run, file, CorebootNvDataGUID, "new", u32(42))
	run(file, "remove", "-g", toolGUID(efiGlobalGUID), "-n", "Timeout")
	out := readFile(t, file)

	got := mustParse(t, out)
	want := map[string][]byte{"power_on_after_fail": u32(0), "debug_level": u32(8), "new": u32(42), "blob": toolVars[3].data}
	if len(got.Variables()) != len(want) {
		t.Fatalf("variables: %s", names(got.Variables()))
	}
	for _, v := range got.Variables() {
		if !bytes.Equal(v.Data, want[v.Name]) {
			t.Errorf("%s = %x, want %x", v.Name, v.Data, want[v.Name])
		}
	}
	checkOracle(t, out, CorebootNvDataGUID, map[string][]byte{
		"power_on_after_fail": u32(0), "debug_level": u32(8), "new": u32(42),
	})
	// And we can keep writing to it.
	mustSet(t, got, CorebootNvDataGUID, "new", u32(43))
	checkOracle(t, got.Bytes(), CorebootNvDataGUID, map[string][]byte{"new": u32(43)})
}
