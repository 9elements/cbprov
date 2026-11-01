package cfr

import "fmt"

const lbHeaderSize = 24 // struct lb_header

// FromCorebootTable finds the LB_TAG_CFR record in a coreboot table dump
// (starting at the "LBIO" header) and parses it. It also returns the raw record.
// A table that only forwards elsewhere yields a ForwardError.
func FromCorebootTable(b []byte) (*Schema, []byte, error) {
	table, err := checkTable(b)
	if err != nil {
		return nil, nil, err
	}
	for off := 0; off < len(table); {
		if len(table)-off < recHdrSize {
			return nil, nil, fmt.Errorf("cfr: truncated coreboot table entry at offset %d", lbHeaderSize+off)
		}
		tag, size := le.Uint32(table[off:]), le.Uint32(table[off+4:])
		if size < recHdrSize || uint64(size) > uint64(len(table)-off) {
			return nil, nil, fmt.Errorf("cfr: coreboot table entry 0x%x at offset %d: size %d out of bounds", tag, lbHeaderSize+off, size)
		}
		rec := table[off : off+int(size)]
		switch tag {
		case lbTagForward:
			if len(rec) < 16 {
				return nil, nil, fmt.Errorf("cfr: short LB_TAG_FORWARD entry at offset %d", lbHeaderSize+off)
			}
			return nil, nil, ForwardError{Addr: le.Uint64(rec[8:])}
		case lbTagCFR:
			s, err := Parse(rec)
			if err != nil {
				return nil, nil, err
			}
			return s, rec, nil
		}
		off += int(size)
	}
	return nil, nil, ErrNoCFR
}

// FindCorebootTable scans a memory dump taken at physical address base for a
// valid lb_header (16-byte aligned, both checksums valid, table inside mem)
// and returns its offset in mem.
func FindCorebootTable(mem []byte, base uint64) (int, error) {
	for off := int((16 - base%16) % 16); off+lbHeaderSize <= len(mem); off += 16 {
		if string(mem[off:off+4]) != "LBIO" {
			continue
		}
		if _, err := checkTable(mem[off:]); err == nil {
			return off, nil
		}
	}
	return 0, ErrNoTable
}

// checkTable validates the lb_header at b[0] and returns the entry bytes.
func checkTable(b []byte) ([]byte, error) {
	if len(b) < lbHeaderSize || string(b[:4]) != "LBIO" {
		return nil, fmt.Errorf("%w: no LBIO signature", ErrNoTable)
	}
	hdrBytes, tableBytes := le.Uint32(b[4:]), le.Uint32(b[12:])
	if hdrBytes != lbHeaderSize {
		return nil, fmt.Errorf("cfr: coreboot table header_bytes %d, want %d", hdrBytes, lbHeaderSize)
	}
	if uint64(hdrBytes)+uint64(tableBytes) > uint64(len(b)) {
		return nil, fmt.Errorf("cfr: coreboot table (%d bytes) exceeds dump of %d bytes", uint64(hdrBytes)+uint64(tableBytes), len(b))
	}
	if ipchksum(b[:hdrBytes]) != 0 {
		return nil, fmt.Errorf("cfr: coreboot table header checksum mismatch")
	}
	table := b[hdrBytes : hdrBytes+tableBytes]
	if want, got := le.Uint32(b[16:]), uint32(ipchksum(table)); want != got {
		return nil, fmt.Errorf("cfr: coreboot table checksum 0x%x, computed 0x%x", want, got)
	}
	return table, nil
}

// ipchksum is coreboot's RFC 1071 checksum over little-endian 16-bit words.
func ipchksum(b []byte) uint16 {
	var sum uint64
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint64(le.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint64(b[len(b)-1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
