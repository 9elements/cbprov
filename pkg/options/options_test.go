package options

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/9elements/cbprov/pkg/cfr"
	"github.com/9elements/cbprov/pkg/efivars"
)

const testSize = 256 * 1024

func testSchema() *cfr.Schema {
	return &cfr.Schema{Forms: []*cfr.Option{{
		Kind: cfr.KindForm, UIName: "Test",
		Options: []*cfr.Option{
			{Kind: cfr.KindBool, Name: "flag", UIName: "Flag", Default: 0},
			{Kind: cfr.KindEnum, Name: "mode", UIName: "Mode", Default: 1, EnumValues: []cfr.EnumValue{
				{Value: 0, UIName: "Alpha"}, {Value: 1, UIName: "Beta"}, {Value: 2, UIName: "Gamma"}}},
			{Kind: cfr.KindNumber, Name: "count", UIName: "Count", Default: 42, Min: 0, Max: 100, Step: 1},
			{Kind: cfr.KindNumber, Name: "locked", UIName: "Locked", Flags: cfr.FlagReadOnly, Max: 10},
			{Kind: cfr.KindVarchar, Name: "label", UIName: "Label", DefaultStr: "hello"},
			{Kind: cfr.KindComment, UIName: "note"},
		},
	}}}
}

func erased() []byte { return bytes.Repeat([]byte{0xff}, testSize) }

func byName(t *testing.T, vals []Value, name string) Value {
	t.Helper()
	for _, v := range vals {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("option %s not listed", name)
	return Value{}
}

func TestErasedShowsDefaults(t *testing.T) {
	s, err := Load(erased(), 0, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Erased() {
		t.Fatal("store should be erased")
	}
	vals, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 5 {
		t.Fatalf("got %d options, want 5 (comments and forms skipped)", len(vals))
	}
	m := byName(t, vals, "mode")
	if m.State != StateDefault || m.Display != "Beta" || m.DefaultStr != "Beta" {
		t.Errorf("mode = %+v", m)
	}
	if c := byName(t, vals, "count"); c.Value != 42 || c.State != StateDefault {
		t.Errorf("count = %+v", c)
	}
}

func TestSetFormatsErasedStoreAndRoundTrips(t *testing.T) {
	region := erased()
	s, err := Load(region, 0, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{"mode": "gamma", "count": "7", "flag": "on"} {
		if err := s.SetValue(name, val); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}
	// Reload from bytes as the next command would.
	s2, err := Load(s.Bytes(), 0, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"mode": "Gamma", "count": "7", "flag": "Enabled"} {
		v, err := s2.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if v.Display != want || v.State != StateSet {
			t.Errorf("%s = %q (%s), want %q set", name, v.Display, v.State, want)
		}
	}
	// What coreboot's efi_option_get_uint() would read: uint32 LE under the coreboot GUID.
	st, err := efivars.Parse(s.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	v, ok := st.Get(efivars.CorebootNvDataGUID, "mode")
	if !ok || len(v.Data) != 4 || binary.LittleEndian.Uint32(v.Data) != 2 {
		t.Errorf("stored mode = %+v", v)
	}
}

func TestValidation(t *testing.T) {
	s, err := Load(erased(), 0, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, val string }{
		{"mode", "Delta"},
		{"mode", "5"},
		{"count", "101"},
		{"count", "-1"},
		{"flag", "maybe"},
		{"locked", "1"},
		{"label", "x"},
		{"unknown", "1"},
	} {
		if err := s.SetValue(tc.name, tc.val); err == nil {
			t.Errorf("%s=%s accepted", tc.name, tc.val)
		}
	}
	if err := s.SetValue("locked", "1"); !errors.Is(err, cfr.ErrReadOnly) {
		t.Errorf("read-only option error = %v", err)
	}
}

func TestRawModeAndReset(t *testing.T) {
	s, err := Load(erased(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetValue("anything", "Gamma"); err == nil {
		t.Error("raw mode accepted a non-number")
	}
	if err := s.SetValue("anything", "0x10"); err != nil {
		t.Fatal(err)
	}
	vals, _ := s.List()
	if v := byName(t, vals, "anything"); v.State != StateRaw || v.Value != 16 {
		t.Errorf("raw = %+v", v)
	}
	found, err := s.Reset("anything")
	if err != nil || !found {
		t.Fatalf("reset: %v %v", found, err)
	}
	if vals, _ := s.List(); len(vals) != 0 {
		t.Errorf("after reset: %+v", vals)
	}
}

func TestResetAllKeepsForeignVariables(t *testing.T) {
	region, err := efivars.Format(testSize, DefaultBlockSize)
	if err != nil {
		t.Fatal(err)
	}
	st, err := efivars.Parse(region)
	if err != nil {
		t.Fatal(err)
	}
	other := efivars.MustParseGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err := st.Set(other, "BootOrder", 7, []byte{1, 0}); err != nil {
		t.Fatal(err)
	}
	s, err := Load(st.Bytes(), 0, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"mode", "count"} {
		if err := s.SetValue(n, "1"); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.ResetAll(); err != nil || n != 2 {
		t.Fatalf("ResetAll = %d, %v", n, err)
	}
	st2, err := efivars.Parse(s.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := st2.Get(other, "BootOrder"); !ok || !bytes.Equal(v.Data, []byte{1, 0}) {
		t.Error("foreign variable lost")
	}
}

func TestWrongSizeIsReported(t *testing.T) {
	region, _ := efivars.Format(testSize, DefaultBlockSize)
	st, _ := efivars.Parse(region)
	if err := st.Set(efivars.CorebootNvDataGUID, "mode", efivars.DefaultAttributes, []byte{1}); err != nil {
		t.Fatal(err)
	}
	s, err := Load(st.Bytes(), 0, testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("mode"); err == nil {
		t.Error("1-byte variable should be reported: coreboot ignores it")
	}
}
