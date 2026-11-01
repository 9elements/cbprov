package vpd

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func ff(n int) []byte { return bytes.Repeat([]byte{0xff}, n) }

var magic = []byte{0xfe, 0x09, 0x01, 'g', 'V', 'p', 'd', 'I', 'n', 'f', 'o', 0x04}

// Golden encoding of serial_number=ABC123 in a 48-byte region, built by hand
// from vpd_tables.h / vpd_decode.c.
var goldenSerial = cat(
	magic,
	[]byte{0x17, 0x00, 0x00, 0x00}, // 23 = 1+1+13+1+6 entry bytes + terminator
	[]byte{0x01, 0x0d}, []byte("serial_number"),
	[]byte{0x06}, []byte("ABC123"),
	[]byte{0x00},
	ff(48-16-23),
)

func TestEncodeGolden(t *testing.T) {
	s := New(48)
	if err := s.Set("serial_number", []byte("ABC123")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, goldenSerial) {
		t.Fatalf("encode mismatch\n got %x\nwant %x", got, goldenSerial)
	}
	if v, ok := cbFind(got, "serial_number"); !ok || string(v) != "ABC123" {
		t.Fatalf("coreboot oracle: %q %v", v, ok)
	}
	if s.EncodedSize() != 16+23 {
		t.Fatalf("EncodedSize = %d", s.EncodedSize())
	}
}

func TestDecodeGolden(t *testing.T) {
	s, err := Decode(goldenSerial)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"serial_number", []byte("ABC123")}}
	if !reflect.DeepEqual(s.Entries, want) || s.Size != 48 {
		t.Fatalf("got %+v size %d", s.Entries, s.Size)
	}
}

func TestLengthEncoding(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x00}},
		{200, []byte{0x81, 0x48}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x81, 0x80, 0x00}},
		{0x12345, []byte{0x84, 0xc6, 0x45}},
	} {
		got := appendLen(nil, tc.n)
		if !bytes.Equal(got, tc.want) || lenSize(tc.n) != len(tc.want) {
			t.Errorf("len %d: got %x (size %d), want %x", tc.n, got, lenSize(tc.n), tc.want)
		}
		var l, dl uint32
		if cbDecodeLen(uint32(len(got)), got, &l, &dl) != decodeOK || int(l) != tc.n || int(dl) != len(got) {
			t.Errorf("len %d: oracle decodes %d/%d", tc.n, l, dl)
		}
	}
}

func TestLongValues(t *testing.T) {
	s := New(0x8000)
	vals := map[string][]byte{
		"k127":   bytes.Repeat([]byte("a"), 127),
		"k128":   bytes.Repeat([]byte("b"), 128),
		"k200":   bytes.Repeat([]byte("c"), 200),
		"k16384": bytes.Repeat([]byte("d"), 16384),
		"empty":  {},
	}
	order := []string{"k127", "k128", "k200", "k16384", "empty"}
	for _, k := range order {
		if err := s.Set(k, vals[k]); err != nil {
			t.Fatal(err)
		}
	}
	long := strings.Repeat("x", 130)
	if err := s.Set(long, []byte("long key")); err != nil {
		t.Fatal(err)
	}
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Spot-check the 200-byte value's two-byte length prefix.
	if i := bytes.Index(b, []byte("\x01\x04k200\x81\x48ccc")); i < 0 {
		t.Fatal("k200 entry not encoded as 01 04 'k200' 81 48 ...")
	}
	d, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d.Entries, s.Entries) {
		t.Fatal("round trip mismatch")
	}
	if !reflect.DeepEqual(cbEntries(b), s.Entries) {
		t.Fatal("coreboot oracle sees different entries")
	}
}

func TestErasedRegion(t *testing.T) {
	s, err := Decode(ff(0x4000))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries) != 0 || s.Size != 0x4000 {
		t.Fatalf("got %+v size %#x", s.Entries, s.Size)
	}
	if _, ok := cbFind(ff(0x4000), "serial_number"); ok {
		t.Fatal("oracle found key in erased region")
	}
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := cat(magic, []byte{1, 0, 0, 0, 0}, ff(0x4000-17))
	if !bytes.Equal(b, want) {
		t.Fatalf("empty store encodes to %x...", b[:20])
	}
}

func TestMissingHeader(t *testing.T) {
	for name, region := range map[string][]byte{
		"zeroed":       make([]byte, 0x1000),
		"garbage":      cat([]byte("hello"), ff(0x100)),
		"bare entries": cat([]byte{0x01, 0x01, 'k', 0x01, 'v', 0x00}, ff(0x100)),
	} {
		if _, err := Decode(region); !errors.Is(err, ErrNoHeader) {
			t.Errorf("%s: err = %v, want ErrNoHeader", name, err)
		}
		if e := cbEntries(region); len(e) != 0 {
			t.Errorf("%s: oracle sees %v", name, e)
		}
	}
}

func TestLegacyOffset(t *testing.T) {
	region := cat(
		[]byte("_SM_"), ff(LegacyOffset-4),
		magic, []byte{0x07, 0, 0, 0},
		[]byte{0x01, 0x01, 'k', 0x03, 'v', 'a', 'l'},
		ff(0x100),
	)
	s, err := Decode(region)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"k", []byte("val")}}
	if !reflect.DeepEqual(s.Entries, want) || !reflect.DeepEqual(cbEntries(region), want) {
		t.Fatalf("got %+v, oracle %+v", s.Entries, cbEntries(region))
	}
	// Encode always writes the modern layout at offset 0; coreboot checks there first.
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, magic) || !reflect.DeepEqual(cbEntries(b), want) {
		t.Fatal("re-encoded legacy region not readable at offset 0")
	}
}

func TestDecodeSkipsInfoAndStops(t *testing.T) {
	body := cat(
		[]byte{0x01, 0x01, 'a', 0x01, '1'},
		[]byte{0xfe, 0x02, 'i', 'i', 0x01, 'x'}, // info entry: skipped by coreboot
		[]byte{0x01, 0x01, 'b', 0x01, '2'},
		[]byte{0xff}, // implicit terminator
		[]byte{0x01, 0x01, 'c', 0x01, '3'},
	)
	region := cat(magic, []byte{byte(len(body)), 0, 0, 0}, body, ff(16))
	s, err := Decode(region)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"a", []byte("1")}, {"b", []byte("2")}}
	if !reflect.DeepEqual(s.Entries, want) || !reflect.DeepEqual(cbEntries(region), want) {
		t.Fatalf("got %+v, oracle %+v", s.Entries, cbEntries(region))
	}
}

func TestDecodeHonoursHeaderSize(t *testing.T) {
	// Entry beyond info.size is invisible to coreboot.
	body := []byte{0x01, 0x01, 'a', 0x01, '1', 0x01, 0x01, 'b', 0x01, '2'}
	region := cat(magic, []byte{5, 0, 0, 0}, body, ff(16))
	s, err := Decode(region)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"a", []byte("1")}}
	if !reflect.DeepEqual(s.Entries, want) || !reflect.DeepEqual(cbEntries(region), want) {
		t.Fatalf("got %+v, oracle %+v", s.Entries, cbEntries(region))
	}
}

func TestDecodeErrors(t *testing.T) {
	hdr := func(n int) []byte { return cat(magic, []byte{byte(n), byte(n >> 8), 0, 0}) }
	for name, region := range map[string][]byte{
		"size too large":   cat(hdr(0x40), ff(0x10)),
		"unknown type":     cat(hdr(5), []byte{0x02, 0x01, 'a', 0x01, '1'}),
		"truncated value":  cat(hdr(5), []byte{0x01, 0x01, 'a', 0x05, '1'}, ff(8)),
		"truncated length": cat(hdr(4), []byte{0x01, 0x01, 'a', 0x81}, ff(8)),
		"huge length":      cat(hdr(8), []byte{0x01, 0x8f, 0xff, 0xff, 0xff, 0x7f, 'a', 'b'}),
		"short for header": magic,
	} {
		if _, err := Decode(region); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestOverflow(t *testing.T) {
	s := New(40)
	if err := s.Set("serial_number", []byte("ABC123")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Encode(); err != nil {
		t.Fatalf("39 bytes into 40: %v", err)
	}
	s.Size = 36
	_, err := s.Encode()
	if err == nil || !strings.Contains(err.Error(), "39 bytes") || !strings.Contains(err.Error(), "3 bytes over") {
		t.Fatalf("err = %v", err)
	}
	s.Size = 39
	if b, err := s.Encode(); err != nil || len(b) != 39 {
		t.Fatalf("exact fit: %v", err)
	}
}

func TestSetDeleteOrder(t *testing.T) {
	s := New(0x1000)
	for _, k := range []string{"a", "b", "c"} {
		if err := s.Set(k, []byte(k+"0")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Set("b", []byte("new")); err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"a", []byte("a0")}, {"b", []byte("new")}, {"c", []byte("c0")}}
	if !reflect.DeepEqual(s.Entries, want) {
		t.Fatalf("after replace: %+v", s.Entries)
	}
	b, _ := s.Encode()
	d, err := Decode(b)
	if err != nil || !reflect.DeepEqual(d.Entries, want) {
		t.Fatalf("round trip: %+v %v", d.Entries, err)
	}

	if !s.Delete("a") || s.Delete("a") {
		t.Fatal("Delete result")
	}
	if err := s.Set("a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	want = []Entry{{"b", []byte("new")}, {"c", []byte("c0")}, {"a", []byte("x")}}
	if !reflect.DeepEqual(s.Entries, want) {
		t.Fatalf("after delete+set: %+v", s.Entries)
	}
}

func TestSetCopiesValue(t *testing.T) {
	s := New(0x100)
	v := []byte("abc")
	_ = s.Set("k", v)
	v[0] = 'X'
	if got, _ := s.Get("k"); string(got) != "abc" {
		t.Fatalf("Set aliases caller slice: %q", got)
	}
}

func TestDuplicates(t *testing.T) {
	body := []byte{
		0x01, 0x01, 'k', 0x01, '1',
		0x01, 0x01, 'j', 0x01, 'x',
		0x01, 0x01, 'k', 0x01, '2',
	}
	region := cat(magic, []byte{byte(len(body)), 0, 0, 0}, body)
	s, err := Decode(region)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get("k"); string(v) != "1" {
		t.Fatalf("Get = %q, coreboot takes the first match", v)
	}
	if v, _ := cbFind(region, "k"); string(v) != "1" {
		t.Fatalf("oracle = %q", v)
	}
	_ = s.Set("k", []byte("3"))
	want := []Entry{{"k", []byte("3")}, {"j", []byte("x")}}
	if !reflect.DeepEqual(s.Entries, want) {
		t.Fatalf("Set should drop shadowed duplicates: %+v", s.Entries)
	}
	s.Entries = append(s.Entries, Entry{"k", []byte("4")})
	if !s.Delete("k") || len(s.Entries) != 1 {
		t.Fatalf("Delete should remove all duplicates: %+v", s.Entries)
	}
}

func TestCheckKey(t *testing.T) {
	for _, k := range []string{"serial_number", "a.b", "X9"} {
		if err := CheckKey(k); err != nil {
			t.Errorf("%q: %v", k, err)
		}
	}
	for _, k := range []string{"", "a b", "a=b", "ü", "a/b"} {
		if err := CheckKey(k); err == nil {
			t.Errorf("%q accepted", k)
		}
		if err := New(0x100).Set(k, nil); err == nil {
			t.Errorf("Set(%q) accepted", k)
		}
	}
	s := &Store{Size: 0x100, Entries: []Entry{{"bad key", nil}}}
	if _, err := s.Encode(); err == nil {
		t.Error("Encode accepted invalid key")
	}
}

func TestCorebootSeesEncodedStore(t *testing.T) {
	s := New(0x4000)
	for _, k := range Keys() {
		v := []byte("value-for-" + k.Name)
		if k.Encoding == EncUUID {
			v, _ = ParseValue(k.Name, "00112233-4455-6677-8899-aabbccddeeff")
		}
		if err := s.Set(k.Name, v); err != nil {
			t.Fatal(err)
		}
	}
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range s.Entries {
		got, ok := cbFind(b, e.Key)
		if !ok || !bytes.Equal(got, e.Value) {
			t.Errorf("%s: oracle got %q %v", e.Key, got, ok)
		}
	}
	if got, _ := cbGets(b, "serial_number", 64); got != "value-for-serial_number" {
		t.Errorf("vpd_gets = %q", got)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(goldenSerial)
	f.Add(ff(64))
	f.Add(cat(magic, []byte{6, 0, 0, 0, 0x01, 0x01, 'k', 0x01, 'v', 0x00}))
	f.Add(cat(magic, []byte{8, 0, 0, 0, 0x01, 0x81, 0x00, 'k', 0x01, 'v', 0xfe, 0x00}))
	f.Fuzz(func(t *testing.T, region []byte) {
		s, err := Decode(region)
		if err != nil {
			return
		}
		// Whatever Decode accepts, coreboot must read identically.
		if got := cbEntries(region); !reflect.DeepEqual(got, s.Entries) && len(got)+len(s.Entries) > 0 {
			t.Fatalf("decode %+v, oracle %+v", s.Entries, got)
		}
		s.Size = s.EncodedSize()
		b, err := s.Encode()
		if err != nil {
			return // stored keys may be invalid names
		}
		d, err := Decode(b)
		if err != nil || !reflect.DeepEqual(d.Entries, s.Entries) && len(d.Entries)+len(s.Entries) > 0 {
			t.Fatalf("re-encode round trip: %v", err)
		}
	})
}
