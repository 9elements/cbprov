//go:build e2e

// Package e2e runs the cbprov CLI against real coreboot images and boots the
// results in QEMU. It needs CBPROV_FIXTURES pointing at the output of
// test/fixtures/build.sh (e.g. .cache/fixtures).
//
// JSON output is matched loosely (objects found by key or by a "name"/"key"
// field) so the tests pin behaviour, not the exact JSON layout.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/9elements/cbprov/test/payload/elfgen"
	"github.com/9elements/cbprov/test/qemu"
)

type fixture struct {
	name       string
	arch       qemu.Arch
	payload    string // elfgen arch
	options    bool   // has the CFR test menu and SMMSTORE
	smbios     bool
	cbfsVerify bool
	vboot      bool
}

var fixtures = []fixture{
	{name: "q35", arch: qemu.Q35, payload: "x86", options: true, smbios: true},
	{name: "q35-cbfsverify", arch: qemu.Q35, payload: "x86", options: true, smbios: true, cbfsVerify: true},
	{name: "q35-vboot", arch: qemu.Q35, payload: "x86", smbios: true, vboot: true},
	{name: "i440fx", arch: qemu.I440FX, payload: "x86", smbios: true},
	{name: "aarch64", arch: qemu.AArch64, payload: "arm64"},
}

const optGUID = "ceae4c1d-335b-4685-a4a0-fc4a94eea085"

var (
	fixturesDir string
	cbprovBin   string
	buildErr    error
	workDir     string
)

func TestMain(m *testing.M) {
	fixturesDir = os.Getenv("CBPROV_FIXTURES")
	if fixturesDir == "" {
		fmt.Println("CBPROV_FIXTURES not set; skipping e2e tests")
		os.Exit(0)
	}
	fixturesDir, _ = filepath.Abs(fixturesDir)
	var err error
	if workDir, err = os.MkdirTemp("", "cbprov-e2e"); err != nil {
		panic(err)
	}
	cbprovBin = filepath.Join(workDir, "cbprov")
	out, err := exec.Command("go", "build", "-o", cbprovBin, "github.com/9elements/cbprov/cmd/cbprov").CombinedOutput()
	if err != nil {
		buildErr = fmt.Errorf("go build ./cmd/cbprov: %v\n%s", err, out)
	}
	code := m.Run()
	os.RemoveAll(workDir)
	os.Exit(code)
}

// forEach runs fn as a parallel subtest for every built fixture matching keep.
func forEach(t *testing.T, keep func(fixture) bool, fn func(t *testing.T, f fixture)) {
	t.Helper()
	for _, f := range fixtures {
		if keep != nil && !keep(f) {
			continue
		}
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			if _, err := os.Stat(f.rom()); err != nil {
				t.Skipf("fixture not built: %v", err)
			}
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			fn(t, f)
		})
	}
}

func (f fixture) rom() string { return filepath.Join(fixturesDir, f.name, "coreboot.rom") }

// copyROM returns a private copy of the fixture image.
func (f fixture) copyROM(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.rom())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), f.name+".rom")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func tool(name string) string { return filepath.Join(fixturesDir, "tools", name) }

type result struct {
	stdout, stderr string
	err            error
}

func run(bin string, args ...string) result {
	var o, e bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	return result{o.String(), e.String(), err}
}

// cbprov runs the CLI and fails the test on a non-zero exit.
func cbprov(t *testing.T, args ...string) string {
	t.Helper()
	r := run(cbprovBin, args...)
	if r.err != nil {
		t.Fatalf("cbprov %s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), r.err, r.stdout, r.stderr)
	}
	return r.stdout
}

// cbprovFails runs the CLI, expects a clean failure and returns stderr.
func cbprovFails(t *testing.T, args ...string) string {
	t.Helper()
	r := run(cbprovBin, args...)
	if r.err == nil {
		t.Fatalf("cbprov %s succeeded, want error\nstdout:\n%s", strings.Join(args, " "), r.stdout)
	}
	if _, ok := r.err.(*exec.ExitError); !ok {
		t.Fatalf("cbprov %s: %v", strings.Join(args, " "), r.err)
	}
	if strings.Contains(r.stderr, "panic:") || strings.Contains(r.stderr, "goroutine ") {
		t.Fatalf("cbprov %s panicked:\n%s", strings.Join(args, " "), r.stderr)
	}
	if strings.TrimSpace(r.stderr) == "" {
		t.Errorf("cbprov %s failed without a message", strings.Join(args, " "))
	}
	return r.stderr
}

func cbprovJSON(t *testing.T, args ...string) any {
	t.Helper()
	out := cbprov(t, append(args, "--json")...)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("cbprov %s --json: invalid JSON: %v\n%s", strings.Join(args, " "), err, out)
	}
	return v
}

func refTool(t *testing.T, name string, args ...string) string {
	t.Helper()
	r := run(tool(name), args...)
	if r.err != nil {
		t.Fatalf("%s %s: %v\n%s%s", name, strings.Join(args, " "), r.err, r.stdout, r.stderr)
	}
	return r.stdout
}

func payloadELF(t *testing.T, arch, msg string) string {
	t.Helper()
	b, err := elfgen.Build(arch, msg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), msg+".elf")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// bootFailures end a boot early: coreboot halts after printing them.
var bootFailures = []string{"verification failure", "Payload not loaded"}

// boot boots rom and waits for all markers. The machine is closed at cleanup.
func boot(t *testing.T, f fixture, rom string, expect ...string) *qemu.Machine {
	t.Helper()
	m, err := tryBoot(t, f, rom, expect, nil, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func tryBoot(t *testing.T, f fixture, rom string, expect, fail []string, timeout time.Duration) (*qemu.Machine, error) {
	t.Helper()
	if !qemu.Available(f.arch) {
		t.Skipf("%s not installed", qemu.Binary(f.arch))
	}
	m, err := qemu.Boot(context.Background(), qemu.Options{
		ROM: rom, Arch: f.arch, Timeout: timeout,
		ExpectSerial: expect, FailSerial: append(fail, bootFailures...),
	})
	if m != nil {
		t.Cleanup(func() { m.Close() })
	}
	return m, err
}

func optLines(vals map[string]uint32) []string {
	var out []string
	for k, v := range vals {
		out = append(out, fmt.Sprintf("CBPROV-OPT %s=%d\n", k, v))
	}
	return out
}

var defaults = map[string]uint32{"cbprov_test_bool": 0, "cbprov_test_enum": 1, "cbprov_test_num": 42}

var (
	schemaMu    sync.Mutex
	schemaCache = map[string]string{}
)

// schemaFor boots the unprovisioned fixture once, dumps its coreboot table and
// returns the path of the cfr.bin extracted from it with cbprov.
func schemaFor(t *testing.T, f fixture) (cfrBin, dump string) {
	t.Helper()
	schemaMu.Lock()
	defer schemaMu.Unlock()
	dir := filepath.Join(workDir, "schema-"+f.name)
	cfrBin, dump = filepath.Join(dir, "cfr.bin"), filepath.Join(dir, "cbtable.bin")
	if _, ok := schemaCache[f.name]; ok {
		return cfrBin, dump
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := boot(t, f, f.rom(), "CBPROV-PAYLOAD-A")
	table, err := m.DumpCorebootTable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dump, table, 0o644); err != nil {
		t.Fatal(err)
	}
	cbprov(t, "schema", "extract", "--from-cbtable", dump, "-o", cfrBin)
	schemaCache[f.name] = cfrBin
	return cfrBin, dump
}

// withSchema returns a copy of the fixture with the CFR schema embedded.
func withSchema(t *testing.T, f fixture) string {
	t.Helper()
	cfrBin, _ := schemaFor(t, f)
	out := filepath.Join(t.TempDir(), "schema.rom")
	cbprov(t, "schema", "embed", f.rom(), cfrBin, "-o", out)
	return out
}

// lookup finds the value stored under name: either a JSON object key, or an
// object whose "name"/"key" field equals name (its "value", or the object).
func lookup(v any, name string) (any, bool) {
	switch x := v.(type) {
	case map[string]any:
		if val, ok := x[name]; ok {
			return val, true
		}
		for _, k := range []string{"name", "key", "opt_name"} {
			if s, ok := x[k].(string); ok && s == name {
				if val, ok := x["value"]; ok {
					return val, true
				}
				return x, true
			}
		}
		for _, c := range x {
			if r, ok := lookup(c, name); ok {
				return r, true
			}
		}
	case []any:
		for _, c := range x {
			if r, ok := lookup(c, name); ok {
				return r, true
			}
		}
	}
	return nil, false
}

// findObject returns the JSON object whose "name" (or "opt_name") is name.
func findObject(v any, name string) (map[string]any, bool) {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range []string{"name", "opt_name"} {
			if s, ok := x[k].(string); ok && s == name {
				return x, true
			}
		}
		for _, c := range x {
			if r, ok := findObject(c, name); ok {
				return r, true
			}
		}
	case []any:
		for _, c := range x {
			if r, ok := findObject(c, name); ok {
				return r, true
			}
		}
	}
	return nil, false
}

// sameValue compares a JSON value with an option value given as number and
// optional enum UI name.
func sameValue(v any, num uint32, uiName string) bool {
	switch x := v.(type) {
	case float64:
		return x == float64(num)
	case bool:
		return x == (num != 0)
	case string:
		return x == uiName || x == strconv.FormatUint(uint64(num), 10)
	case map[string]any:
		for _, k := range []string{"value", "current"} {
			if c, ok := x[k]; ok {
				return sameValue(c, num, uiName)
			}
		}
	}
	return false
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, p string, b []byte) string {
	t.Helper()
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
