package cfr

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file (run with -update to regenerate)", p)
	}
}

func mustParse(t *testing.T, b []byte) *Schema {
	t.Helper()
	s, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseGolden(t *testing.T) {
	blob := sampleBlob()
	golden(t, "cfr.bin", blob)
	s := mustParse(t, blob)
	if want := sampleSchema(); !reflect.DeepEqual(s, want) {
		g, _ := json.MarshalIndent(s, "", "  ")
		w, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("schema mismatch\ngot:  %s\nwant: %s", g, w)
	}
	// Trailing bytes after the record (e.g. CBFS padding) are ignored.
	mustParse(t, append(append([]byte{}, blob...), 0xff, 0xff, 0xff, 0xff))
}

func TestJSON(t *testing.T) {
	s := mustParse(t, sampleBlob())
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "schema.json", append(b, '\n'))
	if !bytes.Contains(b, []byte(`"kind": "varchar"`)) {
		t.Error("kind is not marshalled by name")
	}
	var back Schema
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&back, s) {
		t.Error("JSON round trip changed the schema")
	}
}

func TestOptionsLookup(t *testing.T) {
	s := mustParse(t, sampleBlob())
	var names []string
	for _, o := range s.Options() {
		names = append(names, o.Name)
	}
	want := "s3_enable power_on_after_fail fan_threshold hostname me_state boot_delay lock"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("Options() = %q, want %q", got, want)
	}
	o, ok := s.Lookup("boot_delay")
	if !ok || o.ObjectID != 9 {
		t.Errorf("Lookup(boot_delay) = %v, %v", o, ok)
	}
	if _, ok := s.Lookup("System"); ok {
		t.Error("Lookup found a form by UI name")
	}
}

func TestEnum(t *testing.T) {
	o, _ := mustParse(t, sampleBlob()).Lookup("power_on_after_fail")
	if n, ok := o.EnumName(2); !ok || n != "Keep" {
		t.Errorf("EnumName(2) = %q, %v", n, ok)
	}
	if _, ok := o.EnumName(7); ok {
		t.Error("EnumName(7) found")
	}
	if v, ok := o.EnumValue("kEeP"); !ok || v != 2 {
		t.Errorf("EnumValue(kEeP) = %d, %v", v, ok)
	}
	if _, ok := o.EnumValue("Maybe"); ok {
		t.Error("EnumValue(Maybe) found")
	}
}

func TestValidate(t *testing.T) {
	s := mustParse(t, sampleBlob())
	for _, tc := range []struct {
		name string
		v    uint32
		err  string // substring; empty means valid
	}{
		{"s3_enable", 0, ""},
		{"s3_enable", 1, ""},
		{"s3_enable", 2, "not 0 or 1"},
		{"power_on_after_fail", 1, ""},
		{"power_on_after_fail", 3, "not a listed"},
		{"fan_threshold", 0x10, ""},
		{"fan_threshold", 0x48, ""},
		{"fan_threshold", 0x80, ""},
		{"fan_threshold", 0x44, "step"},
		{"fan_threshold", 0x08, "out of range"},
		{"fan_threshold", 0x88, "out of range"},
		{"boot_delay", 0xffffffff, ""},
		{"hostname", 0, "no numeric value"},
		{"me_state", 0, "volatile"},
		{"lock", 0, "suppressed"},
	} {
		o, ok := s.Lookup(tc.name)
		if !ok {
			t.Fatalf("no option %s", tc.name)
		}
		err := o.Validate(tc.v)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s=%d: %v", tc.name, tc.v, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s=%d: error %v, want %q", tc.name, tc.v, err, tc.err)
		}
	}
	ro := &Option{Kind: KindBool, Name: "x", Flags: FlagReadOnly}
	if err := ro.Validate(0); !errors.Is(err, ErrReadOnly) || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("read-only: %v", err)
	}
}

// corrupt returns a copy of the sample blob after f, with the CRC fixed up.
func corrupt(f func(b []byte) []byte) []byte {
	return fixCRC(f(bytes.Clone(sampleBlob())))
}

// root wraps body records in an lb_cfr header with valid size and CRC.
func root(body ...[]byte) []byte {
	b := u32(nil, lbTagCFR)
	b = append(b, make([]byte, 12)...)
	for _, r := range body {
		b = append(b, r...)
	}
	setSize(b, 0)
	return fixCRC(b)
}

// form wraps child records in a form record.
func form(children ...[]byte) []byte {
	f := encOpt(nil, tOpt{tag: tagForm, ui: "F"})
	for _, c := range children {
		f = append(f, c...)
	}
	setSize(f, 0)
	return f
}

func TestParseErrors(t *testing.T) {
	put := binary.LittleEndian.PutUint32
	const formOff = rootHdrSize
	const formUI = formOff + optHdrSize
	for _, tc := range []struct {
		name string
		b    []byte
		err  string
	}{
		{"empty", nil, "need at least"},
		{"tag", func() []byte { b := sampleBlob(); put(b, 1); return b }(), "root tag"},
		{"version", corrupt(func(b []byte) []byte { put(b[8:], 1); return b }), "version"},
		{"crc", func() []byte { b := sampleBlob(); b[len(b)-1] ^= 1; return b }(), "checksum"},
		{"root size", corrupt(func(b []byte) []byte { put(b[4:], uint32(len(b)+4)); return b }), "root size"},
		{"truncated", sampleBlob()[:100], "root size"},
		{"form size", corrupt(func(b []byte) []byte { put(b[formOff+4:], 0xfffffff0); return b }), "out of bounds"},
		{"small record", corrupt(func(b []byte) []byte { put(b[formOff+4:], 4); return b }), "out of bounds"},
		{"varbinary length", corrupt(func(b []byte) []byte { put(b[formUI+8:], 0x1000); return b }), "data length"},
		{"trailing bytes", root(form(), []byte{1, 2, 3, 4}), "truncated record header"},
		{"top-level option", root(encOpt(nil, tOpt{tag: tagBool, name: "x", ui: "x"})), "top level"},
		{"form header", root(lbRecord(tagForm, make([]byte, 8))), "header"},
		{"numeric header", root(form(lbRecord(tagNumber, make([]byte, 32)))), "header"},
		{"no opt_name", root(form(encOpt(nil, tOpt{tag: tagNumber, ui: "a"}))), "opt_name"},
		{"odd dep values", func() []byte {
			f := encOpt(nil, tOpt{tag: tagForm, ui: "F", deps: []uint32{1}})
			put(f[len(f)-8:], 3) // data_length 4 -> 3
			return root(f)
		}(), "multiple of 4"},
		{"enum value in bool", func() []byte {
			o := encOpt(nil, tOpt{tag: tagEnum, name: "e", ui: "e", enums: []EnumValue{{1, "x"}}})
			put(o, tagBool)
			return root(form(o))
		}(), "not allowed"},
		{"option in option", func() []byte {
			o := encOpt(nil, tOpt{tag: tagBool, name: "b", ui: "b"})
			o = append(o, encOpt(nil, tOpt{tag: tagBool, name: "c", ui: "c"})...)
			setSize(o, 0)
			return root(form(o))
		}(), "not allowed"},
		{"duplicate ui_name", root(form(encVarchar(nil, tagUIName, "G"))), "duplicate"},
		{"deep nesting", func() []byte {
			o := tOpt{tag: tagForm, ui: "leaf"}
			for range maxDepth {
				o = tOpt{tag: tagForm, ui: "n", children: []tOpt{o}}
			}
			return encRoot(o)
		}(), "nested"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(tc.b)
			if err == nil {
				t.Fatalf("parsed: %+v", s)
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Errorf("error %q, want %q", err, tc.err)
			}
		})
	}
}

func TestUnknownTagsSkipped(t *testing.T) {
	b := root(form(encOpt(nil, tOpt{tag: tagBool, name: "a", ui: "A"}), lbRecord(0x99, []byte("future"))),
		lbRecord(0x98, nil))
	s := mustParse(t, b)
	if len(s.Forms) != 1 || len(s.Forms[0].Options) != 1 {
		t.Errorf("got %d forms", len(s.Forms))
	}
}

func sampleTable(cfrRec []byte) []byte {
	mem := make([]byte, 32)
	binary.LittleEndian.PutUint64(mem[8:], 1<<20)
	return encTable(
		lbRecord(0x01, mem),                               // LB_TAG_MEMORY
		lbRecord(0x04, []byte("4.22-test\x00")),           // LB_TAG_VERSION
		lbRecord(0x0f, []byte{1, 0, 0, 0, 0xf8, 3, 0, 0}), // LB_TAG_SERIAL
		cfrRec,                             // LB_TAG_CFR
		lbRecord(0x4b, []byte{0, 0, 0, 0}), // LB_TAG_BOOT_REASON
	)
}

func TestFromCorebootTable(t *testing.T) {
	blob := sampleBlob()
	tbl := sampleTable(blob)
	golden(t, "cbtable.bin", tbl)

	// Low-memory dump based at 0x400 with garbage and a stale LBIO before the table.
	const base, at = 0x400, 0x100
	mem := bytes.Repeat([]byte{0xcc}, 0x1000)
	copy(mem[0x40:], tbl[:lbHeaderSize]) // header without valid table behind it
	mem[0x40+8] ^= 0xff
	copy(mem[at:], tbl)
	off, err := FindCorebootTable(mem, base)
	if err != nil || off != at {
		t.Fatalf("FindCorebootTable = %#x, %v; want %#x", off, err, at)
	}
	s, raw, err := FromCorebootTable(mem[off:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, blob) {
		t.Error("raw CFR record differs")
	}
	if !reflect.DeepEqual(s, sampleSchema()) {
		t.Error("schema differs")
	}

	// A base that shifts alignment by 8 makes the table unaligned.
	if _, err := FindCorebootTable(mem, base+8); !errors.Is(err, ErrNoTable) {
		t.Errorf("unaligned table found: %v", err)
	}
	if _, err := FindCorebootTable(mem[:at+lbHeaderSize+8], base); !errors.Is(err, ErrNoTable) {
		t.Errorf("truncated table found: %v", err)
	}

	noCFR := encTable(lbRecord(0x04, []byte("v\x00")))
	if _, _, err := FromCorebootTable(noCFR); !errors.Is(err, ErrNoCFR) {
		t.Errorf("no CFR: %v", err)
	}
	broken := bytes.Clone(tbl)
	broken[len(broken)-1] ^= 1
	if _, _, err := FromCorebootTable(broken); err == nil || !strings.Contains(err.Error(), "table checksum") {
		t.Errorf("table checksum: %v", err)
	}
}

func TestForward(t *testing.T) {
	fwd := u64(nil, 0x7ffde000)
	tbl := encTable(lbRecord(lbTagForward, fwd))
	mem := append(make([]byte, 0x500), tbl...)
	off, err := FindCorebootTable(mem, 0)
	if err != nil || off != 0x500 {
		t.Fatalf("FindCorebootTable = %#x, %v", off, err)
	}
	_, _, err = FromCorebootTable(mem[off:])
	var fe ForwardError
	if !errors.As(err, &fe) || fe.Addr != 0x7ffde000 {
		t.Errorf("err = %v, want ForwardError{0x7ffde000}", err)
	}
}

func TestCRC32(t *testing.T) {
	// MSB-first init 0xffffffff equals XORing the first 4 bytes with 0xff, so the
	// CRC-32/MPEG-2 check value applies.
	m := []byte("123456789")
	for i := range 4 {
		m[i] ^= 0xff
	}
	if got := crc32(m); got != 0x0376e6e7 {
		t.Errorf("crc32 = %#x, want 0x0376e6e7", got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sampleBlob())
	f.Add(encRoot())
	f.Add(sampleBlob()[:64])
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := Parse(b); err == nil {
			exercise(t, s)
		}
		// Fix the CRC so mutations reach the record walker.
		if s, err := Parse(fixCRC(bytes.Clone(b))); err == nil {
			exercise(t, s)
		}
	})
}

func FuzzFromCorebootTable(f *testing.F) {
	f.Add(sampleTable(sampleBlob()))
	f.Add(encTable(lbRecord(lbTagForward, u64(nil, 1))))
	f.Fuzz(func(t *testing.T, b []byte) {
		FindCorebootTable(b, 0)
		if s, _, err := FromCorebootTable(b); err == nil {
			exercise(t, s)
		}
	})
}

func exercise(t *testing.T, s *Schema) {
	for _, o := range s.Options() {
		o.Validate(o.Default)
		o.EnumName(o.Default)
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatal(err)
	}
}
