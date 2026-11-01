package qemu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// SMBIOS is a parsed SMBIOS table set.
type SMBIOS struct {
	EntryAddr  uint64
	Major      int
	Minor      int
	TableAddr  uint64
	Structures []Structure
}

// Structure is one SMBIOS structure.
type Structure struct {
	Type      uint8
	Handle    uint16
	Formatted []byte // including the 4-byte header
	Strings   []string
}

// Str returns the string referenced by the byte at offset off of the
// formatted area ("" if absent).
func (s Structure) Str(off int) string {
	if off >= len(s.Formatted) {
		return ""
	}
	i := int(s.Formatted[off])
	if i == 0 || i > len(s.Strings) {
		return ""
	}
	return s.Strings[i-1]
}

// System is SMBIOS type 1.
type System struct {
	Manufacturer, ProductName, Version, SerialNumber, UUID, SKU, Family string
}

// Baseboard is SMBIOS type 2.
type Baseboard struct {
	Manufacturer, ProductName, Version, SerialNumber, AssetTag string
}

// Chassis is SMBIOS type 3.
type Chassis struct {
	Manufacturer, Version, SerialNumber, AssetTag string
	Type                                          uint8
}

// Find returns the first structure of type t.
func (s *SMBIOS) Find(t uint8) (Structure, bool) {
	for _, st := range s.Structures {
		if st.Type == t {
			return st, true
		}
	}
	return Structure{}, false
}

// System decodes the type 1 structure.
func (s *SMBIOS) System() (System, error) {
	st, ok := s.Find(1)
	if !ok {
		return System{}, errors.New("no SMBIOS type 1")
	}
	sys := System{Manufacturer: st.Str(4), ProductName: st.Str(5), Version: st.Str(6), SerialNumber: st.Str(7)}
	if len(st.Formatted) >= 0x18 {
		sys.UUID = FormatSMBIOSUUID(st.Formatted[8:24])
	}
	if len(st.Formatted) >= 0x1b {
		sys.SKU, sys.Family = st.Str(0x19), st.Str(0x1a)
	}
	return sys, nil
}

// Baseboard decodes the type 2 structure.
func (s *SMBIOS) Baseboard() (Baseboard, error) {
	st, ok := s.Find(2)
	if !ok {
		return Baseboard{}, errors.New("no SMBIOS type 2")
	}
	return Baseboard{st.Str(4), st.Str(5), st.Str(6), st.Str(7), st.Str(8)}, nil
}

// Chassis decodes the type 3 structure.
func (s *SMBIOS) Chassis() (Chassis, error) {
	st, ok := s.Find(3)
	if !ok || len(st.Formatted) < 9 {
		return Chassis{}, errors.New("no SMBIOS type 3")
	}
	return Chassis{Manufacturer: st.Str(4), Type: st.Formatted[5], Version: st.Str(6), SerialNumber: st.Str(7), AssetTag: st.Str(8)}, nil
}

// FormatSMBIOSUUID formats a UUID in SMBIOS (2.6+) byte order: the first
// three fields are little endian.
func FormatSMBIOSUUID(b []byte) string {
	le := binary.LittleEndian
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", le.Uint32(b), le.Uint16(b[4:]), le.Uint16(b[6:]), b[8:10], b[10:16])
}

func checksum8(b []byte) byte {
	var s byte
	for _, v := range b {
		s += v
	}
	return s
}

// parseEntryPoint decodes an SMBIOS 3.0 ("_SM3_") or 2.x ("_SM_") entry point.
func parseEntryPoint(b []byte) (s *SMBIOS, tableLen int, err error) {
	le := binary.LittleEndian
	switch {
	case len(b) >= 24 && string(b[:5]) == "_SM3_":
		n := int(b[6])
		if n < 24 || n > len(b) || checksum8(b[:n]) != 0 {
			return nil, 0, errors.New("bad _SM3_ entry point")
		}
		return &SMBIOS{Major: int(b[7]), Minor: int(b[8]), TableAddr: le.Uint64(b[16:])}, int(le.Uint32(b[12:])), nil
	case len(b) >= 31 && string(b[:4]) == "_SM_":
		n := int(b[5])
		if n < 31 || n > len(b) || checksum8(b[:n]) != 0 || string(b[16:21]) != "_DMI_" || checksum8(b[16:31]) != 0 {
			return nil, 0, errors.New("bad _SM_ entry point")
		}
		return &SMBIOS{Major: int(b[6]), Minor: int(b[7]), TableAddr: uint64(le.Uint32(b[24:]))}, int(le.Uint16(b[22:])), nil
	}
	return nil, 0, errors.New("no SMBIOS anchor")
}

// ParseStructures parses an SMBIOS structure table up to the end-of-table
// (type 127) structure or the end of b.
func ParseStructures(b []byte) ([]Structure, error) {
	var out []Structure
	for off := 0; off+4 <= len(b); {
		t, l := b[off], int(b[off+1])
		if l < 4 || off+l > len(b) {
			return out, fmt.Errorf("structure at 0x%x has bad length %d", off, l)
		}
		st := Structure{Type: t, Handle: binary.LittleEndian.Uint16(b[off+2:]), Formatted: b[off : off+l]}
		strs := b[off+l:]
		end := bytes.Index(strs, []byte{0, 0})
		if end < 0 {
			return out, fmt.Errorf("unterminated strings in structure at 0x%x", off)
		}
		if end > 0 {
			for _, s := range bytes.Split(strs[:end], []byte{0}) {
				st.Strings = append(st.Strings, string(s))
			}
		}
		out = append(out, st)
		off += l + end + 2
		if t == 127 {
			break
		}
	}
	return out, nil
}

// FindSMBIOS locates and parses the SMBIOS tables: via the CBMEM SMBIOS entry
// of the coreboot table, or on x86 in the legacy F segment.
func (m *Machine) FindSMBIOS() (*SMBIOS, error) {
	var regions []memRange
	if table, err := m.DumpCorebootTable(); err == nil {
		if es, err := CBMEMEntries(table); err == nil {
			for _, e := range es {
				if e.ID == CBMEMIDSMBIOS {
					regions = append(regions, memRange{e.Addr, uint64(e.Size)})
				}
			}
		}
	}
	if m.arch != AArch64 {
		regions = append(regions, memRange{0xf0000, 0x10000})
	}
	for _, r := range regions {
		mem, err := m.ReadMem(r.base, int(r.size))
		if err != nil {
			return nil, err
		}
		for _, anchor := range []string{"_SM3_", "_SM_"} {
			for off := 0; off+len(anchor) <= len(mem); off += 16 {
				if string(mem[off:off+len(anchor)]) != anchor {
					continue
				}
				s, n, err := parseEntryPoint(mem[off:])
				if err != nil {
					continue
				}
				s.EntryAddr = r.base + uint64(off)
				tb, err := m.ReadMem(s.TableAddr, n)
				if err != nil {
					return nil, err
				}
				if s.Structures, err = ParseStructures(tb); err != nil {
					return nil, err
				}
				return s, nil
			}
		}
	}
	return nil, errors.New("SMBIOS entry point not found")
}
