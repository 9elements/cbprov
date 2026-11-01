package vpd

import (
	"bytes"
	"strings"
	"testing"
)

func TestCatalogue(t *testing.T) {
	existing := map[string]bool{
		"serial_number": true, "mlb_serial_number": true, "system_uuid": true,
		"system_product_name": true, "system_sku": true, "system_family": true,
	}
	ks := Keys()
	if len(ks) != 13 {
		t.Fatalf("%d keys", len(ks))
	}
	seen := map[string]bool{}
	for i, k := range ks {
		if seen[k.Name] {
			t.Errorf("duplicate %s", k.Name)
		}
		seen[k.Name] = true
		if k.Proposed == existing[k.Name] {
			t.Errorf("%s: Proposed = %v", k.Name, k.Proposed)
		}
		if i < len(existing) && !existing[k.Name] {
			t.Errorf("existing keys must come first, got %s at %d", k.Name, i)
		}
		if k.SMBIOS == "" || k.Kconfig == "" || strings.HasPrefix(k.Kconfig, "CONFIG_") || k.MaxLen == 0 {
			t.Errorf("%s: incomplete %+v", k.Name, k)
		}
		if err := CheckKey(k.Name); err != nil {
			t.Error(err)
		}
		if got, ok := LookupKey(k.Name); !ok || got != k {
			t.Errorf("LookupKey(%s)", k.Name)
		}
	}
	if _, ok := LookupKey("nope"); ok {
		t.Error("LookupKey(nope)")
	}
	ks[0].Name = "mutated"
	if Keys()[0].Name == "mutated" {
		t.Error("Keys returns the internal slice")
	}
}

func TestUUIDByteOrder(t *testing.T) {
	// Example from coreboot's SMBIOS_UUID_FROM_VPD Kconfig help.
	want := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for _, in := range []string{"00112233-4455-6677-8899-AABBCCDDEEFF", "00112233-4455-6677-8899-aabbccddeeff"} {
		got, err := ParseValue("system_uuid", in)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %x %v", in, got, err)
		}
	}
	if s := FormatValue("system_uuid", want); s != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("FormatValue = %s", s)
	}
	for _, bad := range []string{
		"", "00112233445566778899aabbccddeeff", "00112233-4455-6677-8899-aabbccddeef",
		"0011223g-4455-6677-8899-aabbccddeeff", "0011-233-4455-6677-8899-aabbccddeeff",
		"00112233-4455-6677-8899-aabbcc-deeff", "{0112233-4455-6677-8899-aabbccddeef}",
	} {
		if _, err := ParseValue("system_uuid", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// coreboot ignores a UUID that is not 16 bytes; show it raw.
	if s := FormatValue("system_uuid", []byte{1, 2}); s != "0102" {
		t.Errorf("short uuid: %s", s)
	}
}

func TestParseString(t *testing.T) {
	ok63 := strings.Repeat("A", 63)
	if v, err := ParseValue("serial_number", ok63); err != nil || string(v) != ok63 {
		t.Fatalf("63 chars: %v", err)
	}
	_, err := ParseValue("serial_number", ok63+"B")
	if err == nil || !strings.Contains(err.Error(), "at most 63") {
		t.Fatalf("64 chars: %v", err)
	}
	for _, bad := range []string{"a\tb", "a\x00b", "ä", "x\x7f"} {
		if _, err := ParseValue("system_product_name", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if v, err := ParseValue("asset_tag", ""); err != nil || len(v) != 0 {
		t.Errorf("empty: %v", err)
	}
	if v, err := ParseValue("my_key", "anything\tgoes "+strings.Repeat("x", 100)); err != nil || len(v) != 114 {
		t.Errorf("unknown key: %v", err)
	}
	if _, err := ParseValue("bad key", "x"); err == nil {
		t.Error("invalid key name accepted")
	}
}

func TestStringTruncationMatchesCoreboot(t *testing.T) {
	// A value ParseValue accepts is read by coreboot without truncation.
	v, _ := ParseValue("system_family", strings.Repeat("F", 63))
	s := New(0x200)
	_ = s.Set("system_family", v)
	b, _ := s.Encode()
	if got, _ := cbGets(b, "system_family", 64); got != string(v) {
		t.Fatalf("vpd_gets truncated to %d", len(got))
	}
}

func TestFormatValue(t *testing.T) {
	for _, tc := range []struct {
		key  string
		v    []byte
		want string
	}{
		{"serial_number", []byte("SN 1"), "SN 1"},
		{"serial_number", []byte{0x00, 0x41}, "0041"},
		{"custom", []byte("hello"), "hello"},
		{"custom", []byte{0xde, 0xad}, "dead"},
		{"custom", []byte{}, ""},
	} {
		if got := FormatValue(tc.key, tc.v); got != tc.want {
			t.Errorf("FormatValue(%s, %x) = %q, want %q", tc.key, tc.v, got, tc.want)
		}
	}
	for _, k := range Keys() {
		in := "Value-1.0"
		if k.Encoding == EncUUID {
			in = "12345678-9abc-def0-1234-56789abcdef0"
		}
		v, err := ParseValue(k.Name, in)
		if err != nil {
			t.Fatal(err)
		}
		if out := FormatValue(k.Name, v); out != in {
			t.Errorf("%s: round trip %q -> %q", k.Name, in, out)
		}
	}
}
