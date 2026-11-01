package cbfs

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"slices"
)

// parseSegments decodes SELF segment headers up to the ENTRY segment.
func parseSegments(b []byte) []Segment {
	var segs []Segment
	for len(b) >= segHeaderSize {
		s := Segment{Type: be.Uint32(b), Compression: Compression(be.Uint32(b[4:])),
			Offset: be.Uint32(b[8:]), LoadAddr: be.Uint64(b[12:]), Len: be.Uint32(b[20:]),
			MemLen: be.Uint32(b[24:])}
		segs = append(segs, s)
		if s.Type == SegEntry || len(segs) > 1024 {
			break
		}
		b = b[segHeaderSize:]
	}
	return segs
}

func putSegments(segs []Segment, payload []byte) []byte {
	out := make([]byte, len(segs)*segHeaderSize, len(segs)*segHeaderSize+len(payload))
	for i, s := range segs {
		h := out[i*segHeaderSize:]
		be.PutUint32(h, s.Type)
		be.PutUint32(h[4:], uint32(s.Compression))
		be.PutUint32(h[8:], s.Offset)
		be.PutUint64(h[12:], s.LoadAddr)
		be.PutUint32(h[20:], s.Len)
		be.PutUint32(h[24:], s.MemLen)
	}
	return append(out, payload...)
}

// CBFS master header architectures.
const (
	archX86     = 0x00000001
	archARM     = 0x00000010
	archAArch64 = 0x0000aa64
	archRISCV   = 0xc001d0de
	archPPC64   = 0x407570ff
)

var archMachines = map[uint32][]elf.Machine{
	archX86:     {elf.EM_386, elf.EM_X86_64},
	archARM:     {elf.EM_ARM},
	archAArch64: {elf.EM_AARCH64},
	archRISCV:   {elf.EM_RISCV},
	archPPC64:   {elf.EM_PPC64},
}

// arch returns the architecture from the CBFS master header file, or 0.
func (fs *FS) arch() uint32 {
	buf, es, err := fs.load()
	if err != nil {
		return 0
	}
	for i := range es {
		if es[i].typ == TypeCBFSHeader && es[i].len >= 32 {
			h := es[i].data(buf)
			if be.Uint32(h) == 0x4F524243 {
				return be.Uint32(h[24:])
			}
		}
	}
	return 0
}

type elfProg struct {
	typ, flags              uint32
	off, paddr, filesz, mem uint64
}

// parseELF reads the ELF header and program headers only; like cbfstool it
// ignores section headers, which some ELF writers leave inconsistent.
func parseELF(raw []byte) (elf.Machine, uint64, []elfProg, error) {
	if len(raw) < 52 || string(raw[:4]) != elf.ELFMAG {
		return 0, 0, nil, fmt.Errorf("cbfs: payload is not an ELF file")
	}
	var bo binary.ByteOrder
	switch elf.Data(raw[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		bo = binary.LittleEndian
	case elf.ELFDATA2MSB:
		bo = binary.BigEndian
	default:
		return 0, 0, nil, fmt.Errorf("cbfs: invalid ELF data encoding")
	}
	is64 := elf.Class(raw[elf.EI_CLASS]) == elf.ELFCLASS64
	if !is64 && elf.Class(raw[elf.EI_CLASS]) != elf.ELFCLASS32 || is64 && len(raw) < 64 {
		return 0, 0, nil, fmt.Errorf("cbfs: invalid ELF class")
	}
	machine := elf.Machine(bo.Uint16(raw[18:]))
	var entry, phoff uint64
	var phentsize, phnum uint64
	if is64 {
		entry, phoff = bo.Uint64(raw[24:]), bo.Uint64(raw[32:])
		phentsize, phnum = uint64(bo.Uint16(raw[54:])), uint64(bo.Uint16(raw[56:]))
	} else {
		entry, phoff = uint64(bo.Uint32(raw[24:])), uint64(bo.Uint32(raw[28:]))
		phentsize, phnum = uint64(bo.Uint16(raw[42:])), uint64(bo.Uint16(raw[44:]))
	}
	minEnt := uint64(32)
	if is64 {
		minEnt = 56
	}
	if phentsize < minEnt || phoff > uint64(len(raw)) || phnum*phentsize > uint64(len(raw))-phoff {
		return 0, 0, nil, fmt.Errorf("cbfs: invalid ELF program header table")
	}
	progs := make([]elfProg, phnum)
	for i := range progs {
		h := raw[phoff+uint64(i)*phentsize:]
		p := &progs[i]
		if is64 {
			p.typ, p.flags, p.off, p.paddr = bo.Uint32(h), bo.Uint32(h[4:]), bo.Uint64(h[8:]), bo.Uint64(h[24:])
			p.filesz, p.mem = bo.Uint64(h[32:]), bo.Uint64(h[40:])
		} else {
			p.typ, p.off, p.paddr = bo.Uint32(h), uint64(bo.Uint32(h[4:])), uint64(bo.Uint32(h[12:]))
			p.filesz, p.mem, p.flags = uint64(bo.Uint32(h[16:])), uint64(bo.Uint32(h[20:])), bo.Uint32(h[24:])
		}
	}
	return machine, entry, progs, nil
}

// elfToSELF converts an ELF like cbfstool's parse_elf_to_payload(): one
// segment per non-empty PT_LOAD in program header order (BSS if it has no
// file data, CODE if executable, else DATA), each compressed on its own,
// then an ENTRY segment.
func elfToSELF(raw []byte, comp Compression, arch uint32) ([]byte, error) {
	machine, entry, progs, err := parseELF(raw)
	if err != nil {
		return nil, err
	}
	switch machine {
	case elf.EM_386, elf.EM_X86_64, elf.EM_AARCH64, elf.EM_RISCV:
	default:
		return nil, fmt.Errorf("cbfs: unsupported ELF machine %s", machine)
	}
	if ms, ok := archMachines[arch]; ok && !slices.Contains(ms, machine) {
		return nil, fmt.Errorf("cbfs: %s payload does not match the image architecture", machine)
	}
	var loads []elfProg
	for _, p := range progs {
		if elf.ProgType(p.typ) == elf.PT_LOAD && p.mem != 0 {
			loads = append(loads, p)
		}
	}
	if len(loads) == 0 {
		return nil, fmt.Errorf("cbfs: ELF has no loadable segments")
	}
	hdrLen := uint64(len(loads)+1) * segHeaderSize
	var segs []Segment
	var payload []byte
	for _, p := range loads {
		if p.mem > 0xffffffff || p.filesz > p.mem {
			return nil, fmt.Errorf("cbfs: ELF segment at 0x%x has invalid size", p.paddr)
		}
		s := Segment{LoadAddr: p.paddr, MemLen: uint32(p.mem), Offset: uint32(hdrLen + uint64(len(payload)))}
		if p.filesz == 0 {
			s.Type = SegBSS
			segs = append(segs, s)
			continue
		}
		if p.off > uint64(len(raw)) || p.filesz > uint64(len(raw))-p.off {
			return nil, fmt.Errorf("cbfs: ELF segment at 0x%x exceeds the file", p.paddr)
		}
		s.Type = SegData
		if elf.ProgFlag(p.flags)&elf.PF_X != 0 {
			s.Type = SegCode
		}
		data := raw[p.off : p.off+p.filesz]
		c, err := compress(data, comp)
		if err != nil {
			return nil, err
		}
		if c != nil {
			s.Compression, data = comp, c
		}
		s.Len = uint32(len(data))
		payload = append(payload, data...)
		segs = append(segs, s)
	}
	segs = append(segs, Segment{Type: SegEntry, LoadAddr: entry})
	if uint64(len(payload))+hdrLen > 0xffffffff {
		return nil, fmt.Errorf("cbfs: payload too large")
	}
	return putSegments(segs, payload), nil
}

// flatToSELF wraps a binary like parse_flat_binary_to_payload(): one CODE
// segment and the ENTRY segment.
func flatToSELF(bin []byte, loadAddr, entry uint64, comp Compression) ([]byte, error) {
	if len(bin) == 0 {
		return nil, fmt.Errorf("cbfs: empty payload")
	}
	if uint64(len(bin)) > 0xffffffff-2*segHeaderSize {
		return nil, fmt.Errorf("cbfs: payload too large")
	}
	s := Segment{Type: SegCode, LoadAddr: loadAddr, MemLen: uint32(len(bin)), Offset: 2 * segHeaderSize}
	data := bin
	c, err := compress(bin, comp)
	if err != nil {
		return nil, err
	}
	if c != nil {
		s.Compression, data = comp, c
	}
	s.Len = uint32(len(data))
	return putSegments([]Segment{s, {Type: SegEntry, LoadAddr: entry}}, data), nil
}
