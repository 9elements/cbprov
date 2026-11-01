package qemu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Coreboot table tags and CBMEM IDs used by the harness.
const (
	TagForward    = 0x11
	TagCBMEMEntry = 0x31
	TagCFR        = 0x47

	CBMEMIDSMBIOS = 0x534d4254
	CBMEMIDVPD    = 0x56504420
)

const lbHeaderSize = 24

// CBRecord is one coreboot table record; Data includes the tag/size header.
type CBRecord struct {
	Tag  uint32
	Size uint32
	Data []byte
}

// CBMEMEntry is a decoded LB_TAG_CBMEM_ENTRY record.
type CBMEMEntry struct {
	Addr uint64
	Size uint32
	ID   uint32
}

// ipChecksum is coreboot's compute_ip_checksum().
func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i, v := range b {
		if i&1 != 0 {
			sum += uint32(v) << 8
		} else {
			sum += uint32(v)
		}
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// parseLBHeader validates a coreboot table header at b and returns the size
// of header plus table.
func parseLBHeader(b []byte) (int, error) {
	if len(b) < lbHeaderSize || string(b[:4]) != "LBIO" {
		return 0, errors.New("no LBIO signature")
	}
	le := binary.LittleEndian
	hdrBytes := le.Uint32(b[4:])
	tableBytes := le.Uint32(b[12:])
	if hdrBytes != lbHeaderSize {
		return 0, fmt.Errorf("header_bytes %d", hdrBytes)
	}
	if ipChecksum(b[:lbHeaderSize]) != 0 {
		return 0, errors.New("bad header checksum")
	}
	end := lbHeaderSize + int(tableBytes)
	if tableBytes > 1<<20 || end > len(b) {
		return 0, fmt.Errorf("table_bytes %d out of range", tableBytes)
	}
	if ipChecksum(b[lbHeaderSize:end]) != uint16(le.Uint32(b[16:])) {
		return 0, errors.New("bad table checksum")
	}
	return end, nil
}

// ParseCorebootTable splits a coreboot table (starting at its LBIO header)
// into records.
func ParseCorebootTable(b []byte) ([]CBRecord, error) {
	end, err := parseLBHeader(b)
	if err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint32(b[20:]))
	var recs []CBRecord
	for off := lbHeaderSize; off < end && len(recs) < n; {
		if off+8 > end {
			return nil, fmt.Errorf("truncated record at 0x%x", off)
		}
		tag := binary.LittleEndian.Uint32(b[off:])
		size := binary.LittleEndian.Uint32(b[off+4:])
		if size < 8 || off+int(size) > end {
			return nil, fmt.Errorf("record 0x%x at 0x%x has bad size %d", tag, off, size)
		}
		recs = append(recs, CBRecord{Tag: tag, Size: size, Data: b[off : off+int(size)]})
		off += int(size)
	}
	return recs, nil
}

// CBMEMEntries returns the CBMEM entries listed in a coreboot table.
func CBMEMEntries(table []byte) ([]CBMEMEntry, error) {
	recs, err := ParseCorebootTable(table)
	if err != nil {
		return nil, err
	}
	var es []CBMEMEntry
	for _, r := range recs {
		if r.Tag == TagCBMEMEntry && r.Size >= 24 {
			le := binary.LittleEndian
			es = append(es, CBMEMEntry{Addr: le.Uint64(r.Data[8:]), Size: le.Uint32(r.Data[16:]), ID: le.Uint32(r.Data[20:])})
		}
	}
	return es, nil
}

// findLBIO returns the offset of the first valid coreboot table header in b.
func findLBIO(b []byte, align int) (int, int, bool) {
	for off := 0; ; {
		i := bytes.Index(b[off:], []byte("LBIO"))
		if i < 0 {
			return 0, 0, false
		}
		off += i
		if off%align == 0 {
			if end, err := parseLBHeader(b[off:]); err == nil {
				return off, end, true
			}
		}
		off++
	}
}

type memRange struct{ base, size uint64 }

func (m *Machine) tableSearchRanges() []memRange {
	if m.arch == AArch64 {
		// cbmem sits at the top of DRAM (which starts at 1 GiB).
		top := uint64(0x40000000) + MemSize<<20
		return []memRange{{top - 64<<20, 64 << 20}}
	}
	return []memRange{{0, 0x1000}, {0xf0000, 0x10000}}
}

// DumpCorebootTable locates the coreboot table in guest memory, following a
// forwarding entry if there is one, and returns it from the LBIO header to the
// end of the last record.
func (m *Machine) DumpCorebootTable() ([]byte, error) {
	for _, r := range m.tableSearchRanges() {
		mem, err := m.ReadMem(r.base, int(r.size))
		if err != nil {
			return nil, err
		}
		off, end, ok := findLBIO(mem, 16)
		if !ok {
			continue
		}
		table := mem[off : off+end]
		recs, err := ParseCorebootTable(table)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			if rec.Tag == TagForward && rec.Size >= 16 {
				return m.readTableAt(binary.LittleEndian.Uint64(rec.Data[8:]))
			}
		}
		return bytes.Clone(table), nil
	}
	return nil, errors.New("coreboot table not found")
}

func (m *Machine) readTableAt(addr uint64) ([]byte, error) {
	hdr, err := m.ReadMem(addr, lbHeaderSize)
	if err != nil {
		return nil, err
	}
	if string(hdr[:4]) != "LBIO" {
		return nil, fmt.Errorf("no LBIO header at forward target 0x%x", addr)
	}
	b, err := m.ReadMem(addr, lbHeaderSize+int(binary.LittleEndian.Uint32(hdr[12:])))
	if err != nil {
		return nil, err
	}
	if _, err := parseLBHeader(b); err != nil {
		return nil, fmt.Errorf("coreboot table at 0x%x: %w", addr, err)
	}
	return b, nil
}

// ReadCBMEM returns the contents of the CBMEM entry with the given ID.
func (m *Machine) ReadCBMEM(id uint32) ([]byte, error) {
	table, err := m.DumpCorebootTable()
	if err != nil {
		return nil, err
	}
	es, err := CBMEMEntries(table)
	if err != nil {
		return nil, err
	}
	for _, e := range es {
		if e.ID == id {
			return m.ReadMem(e.Addr, int(e.Size))
		}
	}
	return nil, fmt.Errorf("CBMEM entry 0x%08x not found", id)
}
