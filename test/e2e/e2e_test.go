//go:build e2e

package e2e

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/9elements/cbprov/pkg/cbfs"
	"github.com/9elements/cbprov/pkg/cfr"
	"github.com/9elements/cbprov/pkg/efivars"
	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/test/qemu"
)

var vpdData = map[string]string{
	"serial_number":       "CBPROV-SN-0001",
	"mlb_serial_number":   "CBPROV-MLB-0001",
	"system_product_name": "CBPROV Product",
	"system_sku":          "CBPROV-SKU-7",
	"system_family":       "CBPROV Family",
}

// system_uuid is given in canonical form; coreboot wants the 16 raw bytes in
// SMBIOS order in VPD, which cbprov is expected to produce.
const testUUID = "00112233-4455-6677-8899-aabbccddeeff"

// (a) VPD → SMBIOS.
func TestVPD(t *testing.T) {
	forEach(t, nil, func(t *testing.T, f fixture) {
		in := f.copyROM(t)
		out := filepath.Join(t.TempDir(), "vpd.rom")
		args := []string{"vpd", "set", in, "system_uuid=" + testUUID}
		for k, v := range vpdData {
			args = append(args, k+"="+v)
		}
		orig := readFile(t, in)
		cbprov(t, append(args, "-o", out)...)
		if !bytes.Equal(orig, readFile(t, in)) {
			t.Fatal("vpd set -o modified its input")
		}

		got := cbprovJSON(t, "vpd", "get", out)
		for k, v := range vpdData {
			if val, ok := lookup(got, k); !ok || val != v {
				t.Errorf("vpd get --json: %s = %v, want %q", k, val, v)
			}
		}
		if s := cbprov(t, "vpd", "get", out, "serial_number"); !strings.Contains(s, vpdData["serial_number"]) {
			t.Errorf("vpd get serial_number = %q", s)
		}

		m := boot(t, f, out, "CBPROV-PAYLOAD-A")
		if f.smbios {
			s, err := m.FindSMBIOS()
			if err != nil {
				t.Fatal(err)
			}
			sys, _ := s.System()
			want := qemu.System{
				Manufacturer: sys.Manufacturer, Version: sys.Version,
				ProductName: vpdData["system_product_name"], SerialNumber: vpdData["serial_number"],
				UUID: testUUID, SKU: vpdData["system_sku"], Family: vpdData["system_family"],
			}
			if sys != want {
				t.Errorf("SMBIOS type 1 = %+v\nwant %+v", sys, want)
			}
			if bb, err := s.Baseboard(); err != nil || bb.SerialNumber != vpdData["mlb_serial_number"] {
				t.Errorf("SMBIOS type 2 = %+v, %v", bb, err)
			}
		} else {
			// No SMBIOS on this board: check the VPD coreboot copied to CBMEM.
			blob, err := m.ReadCBMEM(qemu.CBMEMIDVPD)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range vpdData {
				if !bytes.Contains(blob, []byte(k)) || !bytes.Contains(blob, []byte(v)) {
					t.Errorf("CBMEM VPD lacks %s=%s", k, v)
				}
			}
		}

		// rm and --in-place
		cbprov(t, "vpd", "rm", out, "system_sku", "--in-place")
		if v, ok := lookup(cbprovJSON(t, "vpd", "get", out), "system_sku"); ok {
			t.Errorf("system_sku still present after rm: %v", v)
		}
		if v, _ := lookup(cbprovJSON(t, "vpd", "get", out), "serial_number"); v != vpdData["serial_number"] {
			t.Errorf("rm removed other keys: serial_number = %v", v)
		}
	})
}

// (b) schema from a coreboot table dump, embedded, listed.
func TestSchema(t *testing.T) {
	forEach(t, func(f fixture) bool { return f.options }, func(t *testing.T, f fixture) {
		cfrBin, dump := schemaFor(t, f)

		schema, raw, err := cfr.FromCorebootTable(readFile(t, dump))
		if err != nil {
			t.Fatalf("cfr.FromCorebootTable: %v", err)
		}
		if !bytes.Equal(raw, readFile(t, cfrBin)) {
			t.Error("schema extract output differs from the raw LB_TAG_CFR record")
		}
		checkSchema(t, schema)

		img := withSchema(t, f)
		if s, err := cfr.Parse(readFile(t, cfrBin)); err != nil {
			t.Errorf("cfr.Parse(cfr.bin): %v", err)
		} else {
			checkSchema(t, s)
		}
		cbprovJSON(t, "schema", "show", img)
		cbprovJSON(t, "schema", "show", cfrBin)

		for _, args := range [][]string{
			{"option", "list", img},
			{"option", "list", f.rom(), "--schema", cfrBin},
		} {
			list := cbprovJSON(t, args...)
			for name, def := range defaults {
				o, ok := findObject(list, name)
				if !ok {
					t.Errorf("%v: %s missing", args, name)
					continue
				}
				if !sameValue(o["default"], def, "Beta") {
					t.Errorf("%v: %s default = %v, want %d", args, name, o["default"], def)
				}
				if v, ok := o["value"]; ok && !sameValue(v, def, "Beta") {
					t.Errorf("%v: unset %s value = %v, want default %d", args, name, v, def)
				}
			}
		}
	})
}

func checkSchema(t *testing.T, s *cfr.Schema) {
	t.Helper()
	b, ok := s.Lookup("cbprov_test_bool")
	if !ok || b.Kind != cfr.KindBool || b.Default != 0 {
		t.Errorf("cbprov_test_bool = %+v", b)
	}
	e, ok := s.Lookup("cbprov_test_enum")
	if !ok || e.Kind != cfr.KindEnum || e.Default != 1 {
		t.Errorf("cbprov_test_enum = %+v", e)
	} else {
		want := []cfr.EnumValue{{Value: 0, UIName: "Alpha"}, {Value: 1, UIName: "Beta"}, {Value: 2, UIName: "Gamma"}}
		if !slices.Equal(e.EnumValues, want) {
			t.Errorf("cbprov_test_enum values = %+v", e.EnumValues)
		}
	}
	n, ok := s.Lookup("cbprov_test_num")
	if !ok || n.Kind != cfr.KindNumber || n.Default != 42 || n.Min != 0 || n.Max != 100 || n.Step != 1 {
		t.Errorf("cbprov_test_num = %+v", n)
	}
}

// (c) options set/reset, read back by coreboot via get_uint_option.
func TestOptions(t *testing.T) {
	forEach(t, func(f fixture) bool { return f.options }, func(t *testing.T, f fixture) {
		img := withSchema(t, f)
		dir := t.TempDir()
		set := filepath.Join(dir, "set.rom")
		cbprov(t, "option", "set", img, "cbprov_test_enum=Gamma", "cbprov_test_num=7", "-o", set)

		if s := cbprov(t, "option", "get", set, "cbprov_test_enum"); !strings.Contains(s, "Gamma") && !strings.Contains(s, "2") {
			t.Errorf("option get cbprov_test_enum = %q", s)
		}
		list := cbprovJSON(t, "option", "list", set)
		for name, want := range map[string]uint32{"cbprov_test_enum": 2, "cbprov_test_num": 7} {
			if o, ok := findObject(list, name); !ok || !sameValue(o["value"], want, "Gamma") {
				t.Errorf("option list: %s = %v, want %d", name, o, want)
			}
		}

		want := map[string]uint32{"cbprov_test_bool": 0, "cbprov_test_enum": 2, "cbprov_test_num": 7}
		m := boot(t, f, set, append(optLines(want), "CBPROV-PAYLOAD-A")...)

		// The guest must not have disturbed the store.
		flash, err := m.Flash()
		if err != nil {
			t.Fatal(err)
		}
		post := writeFile(t, filepath.Join(dir, "post.rom"), flash)
		if s := cbprov(t, "option", "get", post, "cbprov_test_num"); !strings.Contains(s, "7") {
			t.Errorf("after boot: option get cbprov_test_num = %q", s)
		}

		reset := filepath.Join(dir, "reset.rom")
		cbprov(t, "option", "reset", set, "--all", "-o", reset)
		boot(t, f, reset, append(optLines(defaults), "CBPROV-PAYLOAD-A")...)

		one := filepath.Join(dir, "one.rom")
		cbprov(t, "option", "reset", set, "cbprov_test_num", "-o", one)
		want["cbprov_test_num"] = 42
		boot(t, f, one, append(optLines(want), "CBPROV-PAYLOAD-A")...)

		t.Run("invalid", func(t *testing.T) {
			bad := filepath.Join(dir, "bad.rom")
			for _, kv := range []string{"cbprov_test_num=101", "cbprov_test_enum=Delta", "no_such_option=1", "cbprov_test_bool=2"} {
				cbprovFails(t, "option", "set", img, kv, "-o", bad)
				if _, err := os.Stat(bad); err == nil {
					t.Errorf("option set %s wrote an output file", kv)
					os.Remove(bad)
				}
			}
		})
	})
}

// (d) payload replacement, including the CBFS verification anchor.
func TestPayloadReplace(t *testing.T) {
	forEach(t, nil, func(t *testing.T, f fixture) {
		elfB := payloadELF(t, f.payload, "CBPROV-PAYLOAD-B")
		out := filepath.Join(t.TempDir(), "b.rom")
		if f.vboot {
			stderr := cbprovFails(t, "payload", "replace", f.rom(), "--file", elfB, "-o", out)
			t.Logf("refused: %s", strings.TrimSpace(stderr))
			if _, err := os.Stat(out); err == nil {
				t.Error("refused payload replace still wrote an output file")
			}
			return
		}
		cbprov(t, "payload", "replace", f.rom(), "--file", elfB, "-o", out)
		if s := cbprov(t, "payload", "list", out); !strings.Contains(s, "fallback/payload") {
			t.Errorf("payload list = %q", s)
		}
		if _, err := tryBoot(t, f, out, []string{"CBPROV-PAYLOAD-B"}, []string{"CBPROV-PAYLOAD-A"}, 90*time.Second); err != nil {
			t.Fatal(err)
		}

		for _, comp := range []string{"none", "lz4"} {
			o := filepath.Join(t.TempDir(), comp+".rom")
			cbprov(t, "payload", "replace", f.rom(), "--file", elfB, "--compression", comp, "-o", o)
			boot(t, f, o, "CBPROV-PAYLOAD-B")
		}
	})
}

// Control for (d): on the cbfsverify fixture a metadata change that does not
// update the anchor must stop the boot, so a successful boot after cbprov's
// change proves the anchor was updated.
func TestCBFSVerificationEnforced(t *testing.T) {
	forEach(t, func(f fixture) bool { return f.arch == qemu.Q35 && !f.vboot }, func(t *testing.T, f fixture) {
		b := readFile(t, f.rom())
		i := bytes.Index(b, []byte("build_info\x00"))
		if i < 0 {
			t.Fatal("build_info CBFS file not found")
		}
		b[i] = 'B'
		rom := writeFile(t, filepath.Join(t.TempDir(), "tampered.rom"), b)
		m, err := tryBoot(t, f, rom, []string{"CBPROV-PAYLOAD-A"}, nil, 30*time.Second)
		if f.cbfsVerify {
			if err == nil {
				t.Fatal("tampered CBFS metadata booted; verification not enforced")
			}
			if m == nil || !strings.Contains(m.Serial(), "metadata hash verification failure") {
				t.Fatalf("tampered image failed for another reason: %v", err)
			}
		}
		if !f.cbfsVerify && err != nil {
			t.Fatalf("control without verification failed to boot: %v", err)
		}
	})
}

// (e) apply: VPD, options and payload from one file.
func TestApply(t *testing.T) {
	forEach(t, func(f fixture) bool { return f.options }, func(t *testing.T, f fixture) {
		img := withSchema(t, f)
		dir := t.TempDir()
		elfB := payloadELF(t, f.payload, "CBPROV-PAYLOAD-B")
		yaml := fmt.Sprintf(`vpd:
  serial_number: CBPROV-APPLY-SN
  system_product_name: "CBPROV Apply"
options:
  cbprov_test_bool: 1
  cbprov_test_enum: Alpha
  cbprov_test_num: 99
payload:
  fallback/payload: %s
`, elfB)
		p := writeFile(t, filepath.Join(dir, "provision.yaml"), []byte(yaml))
		out := filepath.Join(dir, "applied.rom")
		cbprov(t, "apply", img, "-f", p, "-o", out)

		want := map[string]uint32{"cbprov_test_bool": 1, "cbprov_test_enum": 0, "cbprov_test_num": 99}
		m := boot(t, f, out, append(optLines(want), "CBPROV-PAYLOAD-B")...)
		s, err := m.FindSMBIOS()
		if err != nil {
			t.Fatal(err)
		}
		if sys, _ := s.System(); sys.SerialNumber != "CBPROV-APPLY-SN" || sys.ProductName != "CBPROV Apply" {
			t.Errorf("SMBIOS type 1 = %+v", sys)
		}
	})
}

// (f) reference tools agree with cbprov.
func TestDifferential(t *testing.T) {
	forEach(t, nil, func(t *testing.T, f fixture) {
		t.Run("cbfs", func(t *testing.T) { diffCBFS(t, f, f.rom()) })
		if !f.vboot {
			t.Run("cbfs-after-replace", func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "b.rom")
				cbprov(t, "payload", "replace", f.rom(), "--file", payloadELF(t, f.payload, "CBPROV-PAYLOAD-B"), "-o", out)
				diffCBFS(t, f, out)
				machine := map[string]string{"x86": "x86", "arm64": "arm64"}[f.payload]
				ext := filepath.Join(t.TempDir(), "payload.elf")
				refTool(t, "cbfstool", out, "extract", "-n", "fallback/payload", "-m", machine, "-f", ext)
				// cbfstool writes section headers debug/elf rejects; the segment bytes suffice.
				b := readFile(t, ext)
				found := bytes.HasPrefix(b, []byte(elf.ELFMAG)) && bytes.Contains(b, []byte("CBPROV-PAYLOAD-B"))
				if !found {
					t.Error("cbfstool-extracted payload is no ELF with CBPROV-PAYLOAD-B")
				}
			})
		}
		if f.options {
			t.Run("smmstore", func(t *testing.T) { diffSMMSTORE(t, f) })
		}
	})
}

type cbfsEntry struct{ name, typ string }

// cbfstoolPrint parses `cbfstool print -v` and fails on any invalid hash.
func cbfstoolPrint(t *testing.T, rom, region string) []cbfsEntry {
	t.Helper()
	out := refTool(t, "cbfstool", rom, "print", "-v", "-r", region)
	if strings.Contains(out, "invalid") {
		t.Errorf("cbfstool reports invalid hashes in %s:\n%s", region, out)
	}
	var es []cbfsEntry
	for _, l := range strings.Split(out, "\n") {
		fs := strings.Fields(l)
		// File lines: name offset type... size comp...; details are indented.
		if len(fs) < 4 || l[0] == ' ' || l[0] == '\t' || !strings.HasPrefix(fs[1], "0x") || fs[0] == "(empty)" {
			continue
		}
		typ := []string{}
		for _, w := range fs[2:] {
			if strings.Trim(w, "0123456789") == "" {
				break
			}
			typ = append(typ, w)
		}
		es = append(es, cbfsEntry{name: fs[0], typ: strings.Join(typ, " ")})
	}
	return es
}

func diffCBFS(t *testing.T, f fixture, rom string) {
	ref := cbfstoolPrint(t, rom, "COREBOOT")
	im, err := image.Open(rom)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := cbfs.Open(im, "COREBOOT")
	if err != nil {
		t.Fatalf("cbfs.Open: %v", err)
	}
	files, err := fs.Files()
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	var got, want []string
	for _, f := range files {
		got = append(got, f.Name)
	}
	for _, e := range ref {
		want = append(want, e.name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("CBFS files\n cbprov:   %v\n cbfstool: %v", got, want)
	}

	cfg := filepath.Join(t.TempDir(), "config")
	refTool(t, "cbfstool", rom, "extract", "-n", "config", "-f", cfg)
	if b, err := fs.Extract("config"); err != nil || !bytes.Equal(b, readFile(t, cfg)) {
		t.Errorf("Extract(config) differs from cbfstool extract (err %v)", err)
	}

	v, err := cbfs.DetectVerification(im)
	if err != nil {
		t.Errorf("DetectVerification: %v", err)
	}
	if v.MetadataHash != f.cbfsVerify || v.Vboot != f.vboot {
		t.Errorf("DetectVerification = %+v, want hash=%v vboot=%v", v, f.cbfsVerify, f.vboot)
	}

	s := cbprov(t, "payload", "list", rom)
	for _, e := range ref {
		if strings.Contains(e.typ, "simple elf") && !strings.Contains(s, e.name) {
			t.Errorf("payload list misses %s:\n%s", e.name, s)
		}
	}
}

// smmstoretool list: "<guid or alias padded>:<name> (<n> bytes)"
func smmstoreList(t *testing.T, rom string) map[string]bool {
	t.Helper()
	vars := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(refTool(t, "smmstoretool", rom, "list")), "\n") {
		g, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(rest, " (")
		vars[strings.TrimSpace(g)+":"+name] = true
	}
	return vars
}

func diffSMMSTORE(t *testing.T, f fixture) {
	img := withSchema(t, f)
	dir := t.TempDir()
	set := filepath.Join(dir, "set.rom")
	cbprov(t, "option", "set", img, "cbprov_test_enum=Gamma", "cbprov_test_num=7", "-o", set)

	vars := smmstoreList(t, set)
	for _, n := range []string{"cbprov_test_enum", "cbprov_test_num"} {
		if !vars["coreboot:"+n] {
			t.Errorf("smmstoretool list lacks %s: %v", n, vars)
		}
	}
	if v := strings.TrimSpace(refTool(t, "smmstoretool", set, "get", "-g", "coreboot", "-n", "cbprov_test_num", "-t", "uint32")); v != "7" {
		t.Errorf("smmstoretool get cbprov_test_num = %q", v)
	}
	if v := strings.TrimSpace(refTool(t, "smmstoretool", set, "get", "-g", "coreboot", "-n", "cbprov_test_enum", "-t", "uint32")); v != "2" {
		t.Errorf("smmstoretool get cbprov_test_enum = %q", v)
	}

	// Library view of the same store.
	im, err := image.Open(set)
	if err != nil {
		t.Fatal(err)
	}
	region, _ := im.RegionData("SMMSTORE")
	st, err := efivars.Parse(region)
	if err != nil {
		t.Fatalf("efivars.Parse: %v", err)
	}
	var libVars []string
	for _, v := range st.Variables() {
		libVars = append(libVars, v.GUID.String()+":"+v.Name)
	}
	if !slices.Contains(libVars, optGUID+":cbprov_test_num") || len(libVars) != len(vars) {
		t.Errorf("efivars variables %v vs smmstoretool %v", libVars, vars)
	}

	// Reference tool writes, cbprov and coreboot read.
	refTool(t, "smmstoretool", set, "set", "-g", "coreboot", "-n", "cbprov_test_num", "-t", "uint32", "-v", "55")
	if s := cbprov(t, "option", "get", set, "cbprov_test_num"); !strings.Contains(s, "55") {
		t.Errorf("option get after smmstoretool set = %q", s)
	}
	boot(t, f, set, "CBPROV-OPT cbprov_test_num=55\n", "CBPROV-PAYLOAD-A")

	// And cbprov writes on top of a store smmstoretool modified.
	again := filepath.Join(dir, "again.rom")
	cbprov(t, "option", "set", set, "cbprov_test_num=8", "-o", again)
	if v := strings.TrimSpace(refTool(t, "smmstoretool", again, "get", "-g", "coreboot", "-n", "cbprov_test_num", "-t", "uint32")); v != "8" {
		t.Errorf("smmstoretool get after second cbprov set = %q", v)
	}
}

// (g) show --json parses on every fixture.
func TestShowJSON(t *testing.T) {
	forEach(t, nil, func(t *testing.T, f fixture) {
		v := cbprovJSON(t, "show", f.rom())
		if _, ok := v.(map[string]any); !ok {
			t.Errorf("show --json is %T, want an object", v)
		}
		if f.options {
			cfrBin, _ := schemaFor(t, f)
			cbprovJSON(t, "show", f.rom(), "--schema", cfrBin)
		}
		if s := cbprov(t, "show", f.rom()); strings.TrimSpace(s) == "" {
			t.Error("show printed nothing")
		}
	})
}

// Corrupt or foreign input must give a clean error, never a panic or output.
func TestCorruptImage(t *testing.T) {
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	good := readFile(t, fixtures[0].rom())
	dir := t.TempDir()
	noFMAP := bytes.Clone(good)
	if i := bytes.Index(noFMAP, []byte("__FMAP__")); i >= 0 {
		copy(noFMAP[i:], "__XXXX__")
	}
	badFMAP := bytes.Clone(good)
	if i := bytes.Index(badFMAP, []byte("__FMAP__")); i >= 0 {
		// Blow up the first area's size (56-byte header, then offset, size).
		copy(badFMAP[i+56+4:], []byte{0xff, 0xff, 0xff, 0x7f})
	}
	badCBFS := bytes.Clone(good)
	if i := bytes.Index(badCBFS, []byte("LARCHIVE")); i >= 0 {
		for j := i; j < i+0x2000 && j < len(badCBFS); j++ {
			badCBFS[j] ^= 0x5a
		}
	}
	cases := map[string][]byte{
		"empty":     {},
		"random":    bytes.Repeat([]byte{0x13, 0x37, 0xc0, 0xde}, 1<<18),
		"truncated": good[:len(good)/3],
		"no-fmap":   noFMAP,
		"bad-fmap":  badFMAP,
		"bad-cbfs":  badCBFS,
	}
	elfB := payloadELF(t, "x86", "CBPROV-PAYLOAD-B")
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			rom := writeFile(t, filepath.Join(dir, name+".rom"), data)
			out := filepath.Join(dir, name+".out")
			cbprovFails(t, "payload", "replace", rom, "--file", elfB, "-o", out)
			if name != "bad-cbfs" {
				// VPD and show only need the FMAP, which bad-cbfs keeps intact.
				cbprovFails(t, "vpd", "set", rom, "serial_number=x", "-o", out)
				cbprovFails(t, "show", rom)
			} else if r := run(cbprovBin, "show", rom, "--json"); strings.Contains(r.stderr, "panic:") {
				t.Errorf("show panicked:\n%s", r.stderr)
			} else if r.err == nil && !json.Valid([]byte(r.stdout)) {
				t.Errorf("show --json on damaged CBFS: invalid JSON")
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("failed command wrote an output file")
			}
		})
	}
	t.Run("missing-file", func(t *testing.T) {
		cbprovFails(t, "show", filepath.Join(dir, "does-not-exist.rom"))
	})
	t.Run("write-needs-output", func(t *testing.T) {
		rom := writeFile(t, filepath.Join(dir, "good.rom"), good)
		cbprovFails(t, "vpd", "set", rom, "serial_number=x")
		if !bytes.Equal(readFile(t, rom), good) {
			t.Error("write without -o/--in-place modified the image")
		}
	})
}
