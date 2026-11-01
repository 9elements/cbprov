package cbfs

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// On-flash layout, see coreboot's commonlib/bsd/cbfs_serialized.h.
const (
	fileMagic      = "LARCHIVE"
	fileHeaderSize = 24
	alignment      = 64  // CBFS_ALIGNMENT
	metadataMax    = 256 // CBFS_METADATA_MAX_SIZE
	attrAlign      = 4
	emptyHeaderLen = fileHeaderSize + 4 // header with name ""
	contentDefault = 0xff

	attrTagUnused      = 0
	attrTagUnused2     = 0xffffffff
	attrTagCompression = 0x42435a4c
	attrTagHash        = 0x68736148

	segHeaderSize = 28
)

// CBFS file types used by this package.
const (
	TypeDeleted    uint32 = 0x00000000
	TypeNull       uint32 = 0xffffffff
	TypeBootblock  uint32 = 0x01
	TypeCBFSHeader uint32 = 0x02
	TypeSELF       uint32 = 0x20
	TypeRaw        uint32 = 0x50
	TypeIntelFIT   uint32 = 0x54
	TypeAMDFW      uint32 = 0x80
)

// Payload segment types (cbfs_payload_segment.type).
const (
	SegCode   uint32 = 0x434F4445
	SegData   uint32 = 0x44415441
	SegBSS    uint32 = 0x42535320
	SegEntry  uint32 = 0x454E5452
	SegParams uint32 = 0x50415241
)

var typeNames = map[uint32]string{
	0x01: "bootblock", 0x02: "cbfs header", 0x10: "legacy stage", 0x11: "stage",
	0x20: "simple elf", 0x21: "fit_payload", 0x30: "optionrom", 0x40: "bootsplash",
	0x50: "raw", 0x51: "vsa", 0x52: "mbi", 0x53: "microcode", 0x54: "intel_fit",
	0x60: "fsp", 0x61: "mrc", 0xaa: "cmos_default", 0x01aa: "cmos_layout", 0xab: "spd",
	0xac: "mrc_cache", 0x62: "mma", 0x63: "efi", 0x70: "struct", 0x00: "deleted",
	0xffffffff: "null", 0x80: "amdfw",
}

// TypeName returns cbfstool's name for a file type.
func TypeName(t uint32) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return "(unknown)"
}

// vboot hash algorithms (enum vb2_hash_algorithm).
type hashAlgo uint8

func (a hashAlgo) size() int {
	switch a {
	case 1:
		return sha1.Size
	case 2:
		return sha256.Size
	case 3:
		return sha512.Size
	case 4:
		return sha256.Size224
	case 5:
		return sha512.Size384
	}
	return 0
}

func (a hashAlgo) new() hash.Hash {
	switch a {
	case 1:
		return sha1.New()
	case 2:
		return sha256.New()
	case 3:
		return sha512.New()
	case 4:
		return sha256.New224()
	case 5:
		return sha512.New384()
	}
	return nil
}

func (a hashAlgo) sum(b []byte) []byte {
	h := a.new()
	h.Write(b)
	return h.Sum(nil)
}

func alignUp(v, a uint32) uint32 { return (v + a - 1) &^ (a - 1) }

var be = binary.BigEndian

// entry is a parsed CBFS file header; offsets are relative to the region.
type entry struct {
	off     uint32
	typ     uint32
	attrOff uint32
	dataOff uint32
	len     uint32
	name    string
}

func (e *entry) empty() bool    { return e.typ == TypeNull || e.typ == TypeDeleted }
func (e *entry) dataStart() int { return int(e.off + e.dataOff) }
func (e *entry) end() uint64    { return uint64(e.off) + uint64(e.dataOff) + uint64(e.len) }
func (e *entry) next() uint64   { return (e.end() + alignment - 1) &^ (alignment - 1) }

func (e *entry) data(buf []byte) []byte { return buf[e.dataStart() : e.dataStart()+int(e.len)] }

func hasMagic(buf []byte, off uint64) bool {
	return off+uint64(len(fileMagic)) <= uint64(len(buf)) && string(buf[off:off+uint64(len(fileMagic))]) == fileMagic
}

func parseEntry(buf []byte, off uint32) (entry, error) {
	if uint64(off)+fileHeaderSize > uint64(len(buf)) {
		return entry{}, fmt.Errorf("cbfs: truncated file header at 0x%x", off)
	}
	h := buf[off:]
	e := entry{off: off, len: be.Uint32(h[8:]), typ: be.Uint32(h[12:]),
		attrOff: be.Uint32(h[16:]), dataOff: be.Uint32(h[20:])}
	if e.dataOff < fileHeaderSize || e.end() > uint64(len(buf)) ||
		(e.attrOff != 0 && (e.attrOff < fileHeaderSize || e.attrOff > e.dataOff)) {
		return entry{}, fmt.Errorf("cbfs: invalid file header at 0x%x", off)
	}
	nameEnd := e.dataOff
	if e.attrOff != 0 {
		nameEnd = e.attrOff
	}
	name := h[fileHeaderSize:nameEnd]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	e.name = string(name)
	return e, nil
}

// walk follows the file chain the way cbfstool does: from offset 0, each next
// header at the 64-byte aligned end of the previous file, until no magic.
func walk(buf []byte) ([]entry, error) {
	var es []entry
	for off := uint64(0); hasMagic(buf, off); {
		e, err := parseEntry(buf, uint32(off))
		if err != nil {
			return nil, err
		}
		es = append(es, e)
		off = e.next()
	}
	return es, nil
}

type attr struct {
	tag uint32
	b   []byte // whole attribute incl. tag and len
}

// attrs lists a file's attributes with cbfstool's iteration rules.
func (e *entry) attrs(buf []byte) []attr {
	if e.attrOff <= fileHeaderSize || e.dataOff <= fileHeaderSize+8 {
		return nil
	}
	h := buf[e.off : e.off+e.dataOff]
	var as []attr
	for a := e.attrOff; a+8 <= e.dataOff; {
		tag, l := be.Uint32(h[a:]), be.Uint32(h[a+4:])
		if l < 8 || l > e.dataOff-a {
			break
		}
		as = append(as, attr{tag, h[a : a+l]})
		a += l
		if a+8 > e.dataOff {
			break
		}
		if t := be.Uint32(h[a:]); t == attrTagUnused || t == attrTagUnused2 {
			break
		}
	}
	return as
}

// compression returns the algorithm and decompressed size of a file.
func (e *entry) compression(buf []byte) (Compression, uint32) {
	comp, size := CompressNone, e.len
	for _, a := range e.attrs(buf) {
		if a.tag == attrTagCompression && len(a.b) >= 16 {
			comp, size = Compression(be.Uint32(a.b[8:])), be.Uint32(a.b[12:])
		}
	}
	return comp, size
}

// fileHash returns the algorithm and digest of the first hash attribute.
func (e *entry) fileHash(buf []byte) (hashAlgo, []byte) {
	for _, a := range e.attrs(buf) {
		if a.tag != attrTagHash || len(a.b) < 12 {
			continue
		}
		algo := hashAlgo(a.b[11])
		if algo.size() == 0 || len(a.b) != 12+algo.size() {
			return 0, nil
		}
		return algo, a.b[12:]
	}
	return 0, nil
}

// metadataHash computes the CBFS metadata hash like cbfs_walk() in
// commonlib/bsd/cbfs_private.c: it scans every 64-byte boundary for a header
// and hashes the metadata (header, name, attributes) of each non-empty file.
func metadataHash(buf []byte, algo hashAlgo) []byte {
	h := algo.new()
	size := uint64(len(buf))
	var md [metadataMax]byte
	off := uint64(0)
	for {
		off = (off + alignment - 1) &^ (alignment - 1)
		for off+fileHeaderSize < size && !hasMagic(buf, off) {
			off += alignment
		}
		if off+fileHeaderSize >= size {
			break
		}
		f := buf[off:]
		attrOff, dataOff := uint64(be.Uint32(f[16:])), uint64(be.Uint32(f[20:]))
		length, typ := uint64(be.Uint32(f[8:])), be.Uint32(f[12:])
		if dataOff < fileHeaderSize || dataOff > metadataMax || length > size || off+dataOff+length > size {
			off += alignment
			continue
		}
		if typ != TypeDeleted && typ != TypeNull && dataOff > fileHeaderSize && dataOff >= attrOff {
			copy(md[:], f[:dataOff])
			// cbfs_walk() forces NUL termination of the name before hashing.
			if attrOff != 0 {
				md[attrOff-1] = 0
			} else {
				md[dataOff-1] = 0
			}
			h.Write(md[:dataOff])
		}
		off += dataOff + length
	}
	return h.Sum(nil)
}
