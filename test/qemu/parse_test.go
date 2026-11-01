package qemu

import (
	"encoding/binary"
	"testing"
)

func buildTable(recs ...[]byte) []byte {
	var body []byte
	for _, r := range recs {
		body = append(body, r...)
	}
	h := make([]byte, lbHeaderSize)
	copy(h, "LBIO")
	le := binary.LittleEndian
	le.PutUint32(h[4:], lbHeaderSize)
	le.PutUint32(h[12:], uint32(len(body)))
	le.PutUint32(h[16:], uint32(ipChecksum(body)))
	le.PutUint32(h[20:], uint32(len(recs)))
	le.PutUint32(h[8:], uint32(ipChecksum(h)))
	return append(h, body...)
}

func record(tag uint32, payload []byte) []byte {
	r := make([]byte, 8, 8+len(payload))
	binary.LittleEndian.PutUint32(r, tag)
	binary.LittleEndian.PutUint32(r[4:], uint32(8+len(payload)))
	return append(r, payload...)
}

func TestCorebootTable(t *testing.T) {
	cbmem := make([]byte, 16)
	binary.LittleEndian.PutUint64(cbmem, 0x7ff00000)
	binary.LittleEndian.PutUint32(cbmem[8:], 0x8000)
	binary.LittleEndian.PutUint32(cbmem[12:], CBMEMIDSMBIOS)
	tbl := buildTable(record(TagCBMEMEntry, cbmem), record(TagCFR, []byte("cfr!")))

	mem := append(make([]byte, 0x40), tbl...)
	mem = append(mem, 0xaa, 0xbb)
	off, end, ok := findLBIO(mem, 16)
	if !ok || off != 0x40 || end != len(tbl) {
		t.Fatalf("findLBIO = %d %d %v", off, end, ok)
	}
	recs, err := ParseCorebootTable(mem[off:])
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[1].Tag != TagCFR || string(recs[1].Data[8:]) != "cfr!" {
		t.Fatalf("records %+v", recs)
	}
	es, err := CBMEMEntries(tbl)
	if err != nil || len(es) != 1 || es[0] != (CBMEMEntry{0x7ff00000, 0x8000, CBMEMIDSMBIOS}) {
		t.Fatalf("CBMEMEntries = %+v, %v", es, err)
	}

	tbl[len(tbl)-1] ^= 1
	if _, err := ParseCorebootTable(tbl); err == nil {
		t.Error("corrupted table accepted")
	}
}

func TestSMBIOS(t *testing.T) {
	uuid := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	t1 := []byte{1, 0x1b, 0x01, 0x00, 1, 2, 0, 3}
	t1 = append(t1, uuid...)
	t1 = append(t1, 6, 4, 5)
	t1 = append(t1, "Emulation\x00QEMU x86\x00SN123\x00SKU1\x00Fam\x00\x00"...)
	t2 := append([]byte{2, 0x0f, 0x02, 0x00, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0}, "Board\x00MLB9\x00\x00"...)
	t127 := []byte{127, 4, 0xff, 0xff, 0, 0}
	tables := append(append(append([]byte{}, t1...), t2...), t127...)

	sts, err := ParseStructures(append(tables, 0xff, 0xff))
	if err != nil {
		t.Fatal(err)
	}
	if len(sts) != 3 {
		t.Fatalf("%d structures", len(sts))
	}
	s := &SMBIOS{Structures: sts}
	sys, err := s.System()
	if err != nil {
		t.Fatal(err)
	}
	want := System{"Emulation", "QEMU x86", "", "SN123", "00112233-4455-6677-8899-aabbccddeeff", "SKU1", "Fam"}
	if sys != want {
		t.Fatalf("System = %+v, want %+v", sys, want)
	}
	if bb, _ := s.Baseboard(); bb.SerialNumber != "MLB9" || bb.Manufacturer != "Board" {
		t.Fatalf("Baseboard = %+v", bb)
	}

	ep := make([]byte, 24)
	copy(ep, "_SM3_")
	ep[6], ep[7], ep[8], ep[10] = 24, 3, 0, 1
	binary.LittleEndian.PutUint32(ep[12:], uint32(len(tables)))
	binary.LittleEndian.PutUint64(ep[16:], 0x7ff00020)
	ep[5] = -checksum8(ep)
	got, n, err := parseEntryPoint(ep)
	if err != nil || got.TableAddr != 0x7ff00020 || n != len(tables) || got.Major != 3 {
		t.Fatalf("parseEntryPoint = %+v %d %v", got, n, err)
	}
	ep[20] ^= 1
	if _, _, err := parseEntryPoint(ep); err == nil {
		t.Error("bad checksum accepted")
	}
}
