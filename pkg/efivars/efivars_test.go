package efivars

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

var (
	efiGlobalGUID = MustParseGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
	imageSecGUID  = MustParseGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
)

func u32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func mustFormat(t *testing.T, size, block int) []byte {
	t.Helper()
	b, err := Format(size, block)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustParse(t *testing.T, b []byte) *Store {
	t.Helper()
	s, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustSet(t *testing.T, s *Store, g GUID, name string, data []byte) {
	t.Helper()
	if err := s.Set(g, name, DefaultAttributes, data); err != nil {
		t.Fatalf("Set %s: %v", name, err)
	}
}

// foreignRecord builds a record as EDK2 would for a time-authenticated
// variable, with non-zero auth fields that must survive untouched.
func foreignRecord(t *testing.T, g GUID, name string, attrs uint32, data []byte) []byte {
	t.Helper()
	raw, err := encodeName(name)
	if err != nil {
		t.Fatal(err)
	}
	rec := encodeRecord(true, g, raw, attrs, data)
	binary.LittleEndian.PutUint64(rec[8:], 0x1122334455667788)
	copy(rec[16:32], "TIMESTAMP-bytes!")
	binary.LittleEndian.PutUint32(rec[32:], 3)
	return rec
}

// appendRaw writes rec behind the last record, as firmware would have.
func appendRaw(t *testing.T, region, rec []byte) []byte {
	t.Helper()
	s := mustParse(t, region)
	if alignUp(len(rec)) > s.Free() {
		t.Fatal("appendRaw: no room")
	}
	out := bytes.Clone(region)
	copy(out[s.free:], rec)
	mustParse(t, out)
	return out
}

func names(vs []Variable) string {
	var n []string
	for _, v := range vs {
		n = append(n, v.Name)
	}
	return strings.Join(n, ",")
}

// smmstoretool (coreboot util/smmstoretool) output after initialising an
// erased 256 KiB file: first 0x64 bytes (FV header + store header).
const smmstoretoolInit256K = "" +
	"00000000000000000000000000000000" + "8d2bf1ff96768b4ca9852747075b4f50" +
	"00000400000000005f465648360e0000" + "4800fff9000000020400000000000100" +
	"0000000000000000782cf3aa7b949a43" + "a1802e144ec37792b8ff00005afe0000" +
	"00000000"

func TestFormatLayout(t *testing.T) {
	b := mustFormat(t, 0x40000, 0x10000)
	want, _ := hex.DecodeString(smmstoretoolInit256K)
	if !bytes.Equal(b[:len(want)], want) {
		t.Fatalf("header mismatch:\n got %x\nwant %x", b[:len(want)], want)
	}
	if !IsErased(b[len(want):]) {
		t.Fatal("rest not erased")
	}

	// coreboot efi_fv_initialize: n - n/2 - 1 blocks for variables.
	for _, tc := range []struct{ size, block, storeSize int }{
		{0x80000, 0x10000, 3*0x10000 - 0x48},
		{0x50000, 0x10000, 2*0x10000 - 0x48}, // odd: smmstoretool would use 1 block
		{0x4000, 0x1000, 0x1000 - 0x48},
	} {
		b := mustFormat(t, tc.size, tc.block)
		if len(b) != tc.size || checksum16(b[:0x48]) != 0 {
			t.Fatalf("%#x: bad length or checksum", tc.size)
		}
		if got := int(binary.LittleEndian.Uint32(b[0x48+16:])); got != tc.storeSize {
			t.Errorf("%#x/%#x: store size %#x, want %#x", tc.size, tc.block, got, tc.storeSize)
		}
		if got := binary.LittleEndian.Uint64(b[32:]); got != uint64(tc.size) {
			t.Errorf("FvLength %#x", got)
		}
		s := mustParse(t, b)
		if len(s.Variables()) != 0 || !bytes.Equal(s.Bytes(), b) {
			t.Error("fresh store not empty or not unchanged")
		}
		if _, err := corebootGetOption(b, CorebootNvDataGUID, "x"); !errors.Is(err, errOracleNotFound) {
			t.Errorf("oracle on fresh store: %v", err)
		}
	}
}

func TestFormatErrors(t *testing.T) {
	for _, tc := range []struct{ size, block int }{
		{0x40000, 0}, {0x40000, -1}, {0x40001, 0x10000}, {0x30000, 0x10000}, {0, 0x1000}, {4 * 16, 16},
	} {
		if _, err := Format(tc.size, tc.block); !errors.Is(err, ErrInvalid) {
			t.Errorf("Format(%#x, %#x) = %v, want ErrInvalid", tc.size, tc.block, err)
		}
	}
}

func TestParseDoesNotAlias(t *testing.T) {
	b := mustFormat(t, 0x4000, 0x1000)
	orig := bytes.Clone(b)
	s := mustParse(t, b)
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	if !bytes.Equal(b, orig) {
		t.Fatal("Parse input modified")
	}
}

func TestSetGetDelete(t *testing.T) {
	s := mustParse(t, mustFormat(t, 0x80000, 0x10000))
	mustSet(t, s, CorebootNvDataGUID, "power_on_after_fail", u32(1))
	mustSet(t, s, CorebootNvDataGUID, "debug_level", u32(7))
	mustSet(t, s, efiGlobalGUID, "Timeout", []byte{5, 0})

	v, ok := s.Get(CorebootNvDataGUID, "debug_level")
	if !ok || !bytes.Equal(v.Data, u32(7)) || v.Attributes != DefaultAttributes || v.GUID != CorebootNvDataGUID {
		t.Fatalf("Get = %+v, %v", v, ok)
	}
	if _, ok := s.Get(efiGlobalGUID, "debug_level"); ok {
		t.Fatal("GUID not part of the key")
	}
	if got := names(s.Variables()); got != "power_on_after_fail,debug_level,Timeout" {
		t.Fatalf("Variables = %s", got)
	}
	checkOracle(t, s.Bytes(), CorebootNvDataGUID, map[string][]byte{
		"power_on_after_fail": u32(1), "debug_level": u32(7), "Timeout": nil,
	})

	// Round trip through bytes.
	s2 := mustParse(t, s.Bytes())
	if fmt.Sprint(s2.Variables()) != fmt.Sprint(s.Variables()) {
		t.Fatal("re-parse differs")
	}

	ok, err := s.Delete(CorebootNvDataGUID, "debug_level")
	if !ok || err != nil {
		t.Fatalf("Delete = %v, %v", ok, err)
	}
	if ok, _ := s.Delete(CorebootNvDataGUID, "debug_level"); ok {
		t.Fatal("second Delete found the variable")
	}
	if _, ok := s.Get(CorebootNvDataGUID, "debug_level"); ok {
		t.Fatal("deleted variable still visible")
	}
	if s.region[s.recs[1].off+2] != stateDeletedFinal {
		t.Fatalf("deleted state %#x", s.region[s.recs[1].off+2])
	}
	checkOracle(t, s.Bytes(), CorebootNvDataGUID, map[string][]byte{
		"power_on_after_fail": u32(1), "debug_level": nil,
	})
	mustParse(t, s.Bytes())
}

func TestSetUpdateAppends(t *testing.T) {
	s := mustParse(t, mustFormat(t, 0x80000, 0x10000))
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	mustSet(t, s, CorebootNvDataGUID, "b", u32(2))
	oldOff := s.recs[0].off
	before := bytes.Clone(s.Bytes())

	mustSet(t, s, CorebootNvDataGUID, "a", u32(3))
	if len(s.recs) != 3 || s.recs[0].off != oldOff || s.recs[0].hdr.state != stateDeletedFinal {
		t.Fatalf("old record not marked deleted in place: %+v", s.recs)
	}
	// Only the old state byte and the appended record changed.
	after := s.Bytes()
	for i := range before {
		if before[i] != after[i] && i != oldOff+2 && i < s.recs[2].off {
			t.Fatalf("unexpected change at %#x", i)
		}
	}
	if got := names(s.Variables()); got != "b,a" {
		t.Fatalf("Variables = %s", got)
	}
	checkOracle(t, after, CorebootNvDataGUID, map[string][]byte{"a": u32(3), "b": u32(2)})
}

func TestSetIdempotent(t *testing.T) {
	s := mustParse(t, mustFormat(t, 0x80000, 0x10000))
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	before := bytes.Clone(s.Bytes())
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	if !bytes.Equal(before, s.Bytes()) {
		t.Fatal("identical Set changed bytes")
	}
	// Same data, different attributes: rewritten.
	if err := s.Set(CorebootNvDataGUID, "a", AttrNonVolatile|AttrBootserviceAccess, u32(1)); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, s.Bytes()) {
		t.Fatal("attribute change not written")
	}
	if v, _ := s.Get(CorebootNvDataGUID, "a"); v.Attributes != 3 {
		t.Fatalf("attributes %#x", v.Attributes)
	}
}

func TestPreservesForeignVariables(t *testing.T) {
	b := mustFormat(t, 0x80000, 0x10000)
	boot := foreignRecord(t, efiGlobalGUID, "Boot0000", 0x7, bytes.Repeat([]byte{0xab}, 77))
	db := foreignRecord(t, imageSecGUID, "db", 0x27, bytes.Repeat([]byte{0xcd}, 301))
	b = appendRaw(t, b, boot)
	b = appendRaw(t, b, db)
	s := mustParse(t, b)
	bootOff, dbOff := s.recs[0].off, s.recs[1].off

	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	mustSet(t, s, CorebootNvDataGUID, "a", u32(2))
	if _, err := s.Delete(CorebootNvDataGUID, "a"); err != nil {
		t.Fatal(err)
	}
	out := s.Bytes()
	if !bytes.Equal(out[bootOff:bootOff+len(boot)], boot) || !bytes.Equal(out[dbOff:dbOff+len(db)], db) {
		t.Fatal("foreign records changed")
	}
	if err := s.Set(imageSecGUID, "db", DefaultAttributes, []byte{1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overwriting authenticated variable: %v", err)
	}
	if v, ok := s.Get(imageSecGUID, "db"); !ok || v.Attributes != 0x27 || len(v.Data) != 301 {
		t.Fatalf("db = %+v", v)
	}
}

func TestReclaim(t *testing.T) {
	b := mustFormat(t, 4*0x1000, 0x1000) // variable area 0x1000-0x48-28 bytes
	// FTW working/spare areas hold data that must survive.
	for i := 0x1000; i < len(b); i++ {
		b[i] = byte(i % 251)
	}
	tail := bytes.Clone(b[0x1000:])
	boot := foreignRecord(t, efiGlobalGUID, "Boot0000", 0x7, bytes.Repeat([]byte{0xab}, 100))
	b = appendRaw(t, b, boot)
	s := mustParse(t, b)
	mustSet(t, s, CorebootNvDataGUID, "a", u32(0))
	db := foreignRecord(t, imageSecGUID, "db", 0x27, bytes.Repeat([]byte{0xcd}, 200))
	s = mustParse(t, appendRaw(t, s.Bytes(), db))
	mustSet(t, s, CorebootNvDataGUID, "b", u32(0xb))
	mustSet(t, s, CorebootNvDataGUID, "c", u32(0xc))

	reclaimed := false
	for i := 1; i < 200; i++ {
		n := len(s.recs)
		mustSet(t, s, CorebootNvDataGUID, "a", u32(uint32(i)))
		if len(s.recs) < n {
			reclaimed = true
			// Reclaim keeps survivors in order and moves the updated one last.
			if got := names(s.Variables()); got != "Boot0000,db,b,c,a" {
				t.Fatalf("after reclaim: %s", got)
			}
			if len(s.recs) != 5 {
				t.Fatalf("deleted records survived reclaim: %d", len(s.recs))
			}
		} else if len(s.recs) != n+1 {
			t.Fatalf("set %d: records %d -> %d", i, n, len(s.recs))
		}
		checkOracle(t, s.Bytes(), CorebootNvDataGUID, map[string][]byte{"a": u32(uint32(i)), "b": u32(0xb)})
	}
	if !reclaimed {
		t.Fatal("no reclaim happened")
	}
	if !bytes.Contains(s.Bytes(), boot) || !bytes.Contains(s.Bytes(), db) {
		t.Fatal("foreign records not byte-identical after reclaim")
	}
	if !bytes.Equal(s.Bytes()[0x1000:], tail) {
		t.Fatal("FTW area changed")
	}
	mustParse(t, s.Bytes())
}

func TestStoreFull(t *testing.T) {
	s := mustParse(t, mustFormat(t, 4*0x1000, 0x1000))
	mustSet(t, s, CorebootNvDataGUID, "x", u32(1))
	mustSet(t, s, CorebootNvDataGUID, "x", u32(2)) // leaves a deleted record
	var err error
	for i := 0; err == nil; i++ {
		err = s.Set(CorebootNvDataGUID, fmt.Sprintf("v%d", i), DefaultAttributes, make([]byte, 300))
		if i > 100 {
			t.Fatal("store never filled")
		}
	}
	if !errors.Is(err, ErrStoreFull) {
		t.Fatalf("err = %v", err)
	}
	before := bytes.Clone(s.Bytes())
	if err := s.Set(CorebootNvDataGUID, "big", DefaultAttributes, make([]byte, 0x1000)); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(before, s.Bytes()) {
		t.Fatal("failed Set changed the store")
	}
	mustParse(t, s.Bytes())
	checkOracle(t, s.Bytes(), CorebootNvDataGUID, map[string][]byte{"x": u32(2)})
}

func TestExactFit(t *testing.T) {
	s := mustParse(t, mustFormat(t, 4*0x1000, 0x1000))
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	n := s.Free() - authHeaderLen - 4 // name "f" + NUL
	data := bytes.Repeat([]byte{0x5a}, n)
	mustSet(t, s, CorebootNvDataGUID, "f", data)
	if s.Free() != 0 {
		t.Fatalf("free = %d", s.Free())
	}
	s = mustParse(t, s.Bytes())
	checkOracle(t, s.Bytes(), CorebootNvDataGUID, map[string][]byte{"a": u32(1), "f": data})

	// Full store: an update reclaims the old copy and fits again.
	data[0] = 1
	mustSet(t, s, CorebootNvDataGUID, "f", data)
	checkOracle(t, s.Bytes(), CorebootNvDataGUID, map[string][]byte{"a": u32(1), "f": data})
}

func TestPlainStore(t *testing.T) {
	b := mustFormat(t, 0x40000, 0x10000)
	copy(b[0x48:], variableGUID[:])
	s := mustParse(t, b)
	mustSet(t, s, CorebootNvDataGUID, "a", u32(9))
	if s.auth || s.recs[0].size != plainHeaderLen+4+4 {
		t.Fatalf("plain header not used: %+v", s.recs[0])
	}
	mustSet(t, s, CorebootNvDataGUID, "a", u32(10))
	checkOracle(t, s.Bytes(), CorebootNvDataGUID, map[string][]byte{"a": u32(10)})
}

// Interrupted EDK2/coreboot updates: lookup prefers a complete VAR_ADDED copy
// over an in-transition one, and skips header-only records.
func TestInterruptedUpdates(t *testing.T) {
	raw, _ := encodeName("a")
	rec := func(state byte, v uint32) []byte {
		r := encodeRecord(true, CorebootNvDataGUID, raw, DefaultAttributes, u32(v))
		r[2] = state
		return r
	}
	b := mustFormat(t, 0x40000, 0x10000)
	b = appendRaw(t, b, rec(stateTransition, 1))
	b = appendRaw(t, b, rec(stateHeaderValidOnly, 2))
	if v, ok := mustParse(t, b).Get(CorebootNvDataGUID, "a"); !ok || !bytes.Equal(v.Data, u32(1)) {
		t.Fatalf("transition-only: %+v %v", v, ok)
	}
	checkOracle(t, b, CorebootNvDataGUID, map[string][]byte{"a": u32(1)})

	b2 := appendRaw(t, b, rec(stateAdded, 3))
	s := mustParse(t, b2)
	if v, _ := s.Get(CorebootNvDataGUID, "a"); !bytes.Equal(v.Data, u32(3)) || len(s.Variables()) != 1 {
		t.Fatalf("added copy not preferred: %+v", s.Variables())
	}
	checkOracle(t, b2, CorebootNvDataGUID, map[string][]byte{"a": u32(3)})

	// Identical Set on an in-transition copy is a no-op, like EDK2.
	s = mustParse(t, b)
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	if !bytes.Equal(s.Bytes(), b) {
		t.Fatal("no-op Set changed bytes")
	}
	// A real update deletes the in-transition copy.
	mustSet(t, s, CorebootNvDataGUID, "a", u32(4))
	if s.recs[0].hdr.state != stateDeletedFinal || s.recs[1].hdr.state != stateHeaderValidOnly {
		t.Fatalf("states %#x %#x", s.recs[0].hdr.state, s.recs[1].hdr.state)
	}
	checkOracle(t, s.Bytes(), CorebootNvDataGUID, map[string][]byte{"a": u32(4)})

	// Reclaim promotes a lone in-transition copy to VAR_ADDED and drops
	// header-only records.
	s = mustParse(t, b)
	if err := s.reclaim(varKey{}, encodeRecord(true, CorebootNvDataGUID, []byte{'z', 0, 0, 0}, 7, u32(5))); err != nil {
		t.Fatal(err)
	}
	if len(s.recs) != 2 || s.recs[0].hdr.state != stateAdded || names(s.Variables()) != "a,z" {
		t.Fatalf("after reclaim: %+v", s.recs)
	}
}

func TestNames(t *testing.T) {
	s := mustParse(t, mustFormat(t, 0x40000, 0x10000))
	for _, n := range []string{"Länge€", "clef\U0001D11E"} {
		mustSet(t, s, CorebootNvDataGUID, n, []byte(n))
		if v, ok := mustParse(t, s.Bytes()).Get(CorebootNvDataGUID, n); !ok || v.Name != n {
			t.Fatalf("%q round trip: %+v", n, v)
		}
	}
	raw, _ := encodeName("Ab")
	if !bytes.Equal(raw, []byte{'A', 0, 'b', 0, 0, 0}) {
		t.Fatalf("encodeName = %x", raw)
	}
	for _, n := range []string{"", "a\x00b", "\xff"} {
		if err := s.Set(CorebootNvDataGUID, n, DefaultAttributes, u32(1)); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q: %v", n, err)
		}
	}
}

func TestSetArgumentErrors(t *testing.T) {
	s := mustParse(t, mustFormat(t, 0x40000, 0x10000))
	for _, a := range []uint32{0, AttrBootserviceAccess, AttrNonVolatile | AttrRuntimeAccess, 0x17, 0x27, 0x47, 0x107} {
		if err := s.Set(CorebootNvDataGUID, "a", a, u32(1)); !errors.Is(err, ErrInvalid) {
			t.Errorf("attrs %#x: %v", a, err)
		}
	}
	if err := s.Set(CorebootNvDataGUID, "a", DefaultAttributes, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty data: %v", err)
	}
	if err := s.Set(CorebootNvDataGUID, "a", DefaultAttributes|attrHardwareErrorRecord, u32(1)); err != nil {
		t.Errorf("HR attribute: %v", err)
	}
}

func TestRegionLargerThanVolume(t *testing.T) {
	b := append(mustFormat(t, 0x4000, 0x1000), bytes.Repeat([]byte{0x42}, 100)...)
	s := mustParse(t, b)
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	if len(s.Bytes()) != len(b) || !bytes.Equal(s.Bytes()[0x4000:], b[0x4000:]) {
		t.Fatal("data behind the volume changed")
	}
}

func TestCorrupt(t *testing.T) {
	base := mustFormat(t, 0x40000, 0x10000)
	s := mustParse(t, base)
	mustSet(t, s, CorebootNvDataGUID, "a", u32(1))
	good := s.Bytes()
	recOff := 0x64
	fixSum := func(b []byte) {
		binary.LittleEndian.PutUint16(b[50:], 0)
		binary.LittleEndian.PutUint16(b[50:], -checksum16(b[:0x48]))
	}
	for _, tc := range []struct {
		name string
		mut  func(b []byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:0x40] }},
		{"erased", func(b []byte) []byte { return bytes.Repeat([]byte{0xff}, len(b)) }},
		{"signature", func(b []byte) []byte { b[40] = 'x'; return b }},
		{"revision", func(b []byte) []byte { b[55] = 1; fixSum(b); return b }},
		{"checksum", func(b []byte) []byte { b[50]++; return b }},
		{"fv guid", func(b []byte) []byte { b[16]++; fixSum(b); return b }},
		{"fv length > region", func(b []byte) []byte { return b[:0x30000] }},
		{"odd header length", func(b []byte) []byte { b[48] = 0x49; fixSum(b); return b }},
		{"block map", func(b []byte) []byte { b[56] = 3; fixSum(b); return b }},
		{"store guid", func(b []byte) []byte { b[0x48]++; return b }},
		{"store size", func(b []byte) []byte { copy(b[0x48+16:], u32(0x40000)); return b }},
		{"store tiny", func(b []byte) []byte { copy(b[0x48+16:], u32(28)); return b }},
		{"not formatted", func(b []byte) []byte { b[0x48+20] = 0xff; return b }},
		{"not healthy", func(b []byte) []byte { b[0x48+21] = 0xff; return b }},
		{"bad state", func(b []byte) []byte { b[recOff+2] = 0x12; return b }},
		{"garbage after last", func(b []byte) []byte { b[recOff+0x200] = 0; return b }},
		{"name size odd", func(b []byte) []byte { copy(b[recOff+36:], u32(3)); return b }},
		{"unterminated name", func(b []byte) []byte { b[recOff+60+2] = 'x'; return b }},
		{"overflow", func(b []byte) []byte { copy(b[recOff+40:], u32(0x20000)); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.mut(bytes.Clone(good))
			if _, err := Parse(b); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Parse: %v", err)
			}
			// The oracle must agree that coreboot rejects it.
			if _, err := corebootGetOption(b, CorebootNvDataGUID, "a"); !errors.Is(err, errOracleCorrupt) {
				t.Fatalf("oracle: %v", err)
			}
		})
	}
}

func TestGUIDString(t *testing.T) {
	const s = "ceae4c1d-335b-4685-a4a0-fc4a94eea085"
	if CorebootNvDataGUID.String() != s {
		t.Fatal(CorebootNvDataGUID.String())
	}
	if !bytes.Equal(CorebootNvDataGUID[:4], []byte{0x1d, 0x4c, 0xae, 0xce}) {
		t.Fatal("not mixed-endian")
	}
}
