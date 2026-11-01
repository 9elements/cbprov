// Package cbfs lists, extracts, removes and adds CBFS files inside a coreboot
// image, and maintains CBFS_VERIFICATION metadata (file hash attributes and
// the bootblock's metadata hash anchor). Allocation follows cbfstool so that
// edits produce the same layout cbfstool would.
package cbfs

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/9elements/cbprov/pkg/image"
)

// ErrNotImplemented marks API that is still being built.
var ErrNotImplemented = errors.New("cbfs: not implemented")

// ErrNotFound is returned when a named file does not exist.
var ErrNotFound = errors.New("cbfs: file not found")

// Compression algorithms, values as in cbfs_serialized.h.
type Compression uint32

const (
	CompressNone Compression = 0
	CompressLZMA Compression = 1
	CompressLZ4  Compression = 2
	CompressZSTD Compression = 3 // read-only: listed, not decompressed
)

func (c Compression) String() string {
	switch c {
	case CompressNone:
		return "none"
	case CompressLZMA:
		return "lzma"
	case CompressLZ4:
		return "lz4"
	case CompressZSTD:
		return "zstd"
	}
	return "unknown"
}

// File describes one CBFS file.
type File struct {
	Name        string
	Type        uint32
	TypeName    string
	Offset      uint32 // of the file header, relative to the CBFS region
	Size        uint32 // stored data size
	Compression Compression
	DecompSize  uint32 // 0 if uncompressed
	// Segments of a SELF payload (Type 0x20); payloads compress per segment.
	Segments []Segment
}

// Segment is one SELF payload segment header.
type Segment struct {
	Type        uint32
	Compression Compression
	Offset      uint32 // of the segment data, relative to the payload start
	LoadAddr    uint64
	Len         uint32
	MemLen      uint32
}

// Verification describes how the image is protected; payload changes need it.
type Verification struct {
	// MetadataHash is true if a CBFS metadata hash anchor was found in the bootblock.
	MetadataHash bool
	// Vboot is true if the image has vboot RW slots (FW_MAIN_A/B).
	Vboot bool
}

// FS is one CBFS region of an image.
type FS struct {
	im     *image.Image
	region string
}

// Open opens the CBFS in the given FMAP region ("COREBOOT" for the RO CBFS).
func Open(im *image.Image, region string) (*FS, error) {
	buf, err := im.RegionData(region)
	if err != nil {
		return nil, err
	}
	if !hasMagic(buf, 0) {
		return nil, fmt.Errorf("cbfs: region %s is not a CBFS", region)
	}
	if _, err := walk(buf); err != nil {
		return nil, fmt.Errorf("region %s: %w", region, err)
	}
	return &FS{im: im, region: region}, nil
}

func (fs *FS) load() ([]byte, []entry, error) {
	buf, err := fs.im.RegionData(fs.region)
	if err != nil {
		return nil, nil, err
	}
	es, err := walk(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("region %s: %w", fs.region, err)
	}
	return buf, es, nil
}

// Files lists all non-empty files in order.
func (fs *FS) Files() ([]File, error) {
	buf, es, err := fs.load()
	if err != nil {
		return nil, err
	}
	var files []File
	for i := range es {
		e := &es[i]
		if e.empty() {
			continue
		}
		f := File{Name: e.name, Type: e.typ, TypeName: TypeName(e.typ), Offset: e.off, Size: e.len}
		f.Compression, f.DecompSize = e.compression(buf)
		if f.Compression == CompressNone {
			f.DecompSize = 0
		}
		if e.typ == TypeSELF {
			f.Segments = parseSegments(e.data(buf))
		}
		files = append(files, f)
	}
	return files, nil
}

// Free returns the data capacity of the largest empty space once adjacent
// empty files are merged (what cbfstool print shows for that "(empty)" file).
// A new file also needs room for its header, name and attributes.
func (fs *FS) Free() (uint32, error) {
	buf, es, err := fs.load()
	if err != nil {
		return 0, err
	}
	var best uint32
	for _, s := range emptySpans(es, len(buf)) {
		if s.end-s.start > emptyHeaderLen {
			best = max(best, uint32(s.end-s.start-emptyHeaderLen))
		}
	}
	return best, nil
}

// Extract returns the decompressed contents of a file. SELF payloads are
// returned as stored (segments stay compressed), like cbfstool extract -U.
func (fs *FS) Extract(name string) ([]byte, error) {
	buf, es, err := fs.load()
	if err != nil {
		return nil, err
	}
	e := find(es, name)
	if e == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	comp, size := e.compression(buf)
	out, err := decompress(e.data(buf), comp, size)
	if err != nil {
		return nil, fmt.Errorf("cbfs: %s: %w", name, err)
	}
	return out, nil
}

func find(es []entry, name string) *entry {
	for i := range es {
		if !es[i].empty() && es[i].name == name {
			return &es[i]
		}
	}
	return nil
}

func decompress(data []byte, comp Compression, size uint32) ([]byte, error) {
	var out []byte
	var err error
	switch comp {
	case CompressNone:
		return bytes.Clone(data), nil
	case CompressLZMA:
		out, err = lzmaDecompress(data, uint64(size))
	case CompressLZ4:
		out, err = lz4Decompress(data, uint64(size))
	default:
		return nil, fmt.Errorf("unsupported compression %s (%d)", comp, uint32(comp))
	}
	if err != nil {
		return nil, err
	}
	if len(out) != int(size) {
		return nil, fmt.Errorf("decompressed to %d bytes, expected %d", len(out), size)
	}
	return out, nil
}

// compress returns nil if compression is unsupported or does not pay off.
func compress(data []byte, comp Compression) ([]byte, error) {
	var out []byte
	switch comp {
	case CompressNone:
		return nil, nil
	case CompressLZMA:
		out = lzmaCompress(data)
	case CompressLZ4:
		out = lz4Compress(data)
	default:
		return nil, fmt.Errorf("cbfs: cannot compress with %s", comp)
	}
	if len(out) >= len(data) {
		return nil, nil
	}
	return out, nil
}

// Remove deletes a file and merges the freed space.
func (fs *FS) Remove(name string) error {
	buf, es, err := fs.load()
	if err != nil {
		return err
	}
	e := find(es, name)
	if e == nil {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	be.PutUint32(buf[e.off+12:], TypeDeleted)
	if _, err := mergeEmpty(buf); err != nil {
		return err
	}
	return fs.afterChange()
}

// AddRaw adds a raw file.
func (fs *FS) AddRaw(name string, data []byte, comp Compression) error {
	var attrs [][]byte
	c, err := compress(data, comp)
	if err != nil {
		return err
	}
	if c != nil {
		attrs = append(attrs, compressionAttr(comp, uint32(len(data))))
		data = c
	}
	return fs.add(name, TypeRaw, data, attrs)
}

// AddPayloadELF converts an ELF to SELF and adds it as a payload.
func (fs *FS) AddPayloadELF(name string, elf []byte, comp Compression) error {
	self, err := elfToSELF(elf, comp, fs.arch())
	if err != nil {
		return err
	}
	return fs.add(name, TypeSELF, self, nil)
}

// AddPayloadFlat adds a flat binary as a payload loaded at loadAddr and entered at entry.
func (fs *FS) AddPayloadFlat(name string, bin []byte, loadAddr, entry uint64, comp Compression) error {
	self, err := flatToSELF(bin, loadAddr, entry, comp)
	if err != nil {
		return err
	}
	return fs.add(name, TypeSELF, self, nil)
}

// afterChange refreshes the metadata hash when a main CBFS changed, as
// cbfstool does after every add/remove.
func (fs *FS) afterChange() error {
	for _, c := range anchorContainers {
		if c.cbfs == fs.region {
			return UpdateMetadataHash(fs.im)
		}
	}
	return nil
}

// DetectVerification reports CBFS verification and vboot state of an image.
func DetectVerification(im *image.Image) (Verification, error) {
	v := Verification{Vboot: im.HasRegion("FW_MAIN_A")}
	for _, c := range anchorContainers {
		a, err := findAnchor(im, c)
		if err != nil {
			return v, err
		}
		if a != nil {
			v.MetadataHash = true
		}
	}
	return v, nil
}

// UpdateMetadataHash recomputes the metadata hash of the RO CBFS and stores it
// in the bootblock's anchor, together with the FMAP hash. It is a no-op if the
// image has no anchor.
func UpdateMetadataHash(im *image.Image) error {
	for _, c := range anchorContainers {
		a, err := findAnchor(im, c)
		if err != nil {
			return err
		}
		if a == nil {
			continue
		}
		buf, err := im.RegionData(c.cbfs)
		if err != nil {
			return err
		}
		copy(a.cbfsHash(), metadataHash(buf, a.algo))
		fh, err := fmapHash(im, a.algo)
		if err != nil {
			return err
		}
		copy(a.fmapHash(), fh)
	}
	return nil
}

func validName(name string) error {
	switch {
	case name == "":
		return errors.New("cbfs: empty file name")
	case strings.HasPrefix(name, "["):
		return fmt.Errorf("cbfs: file name %q must not start with '['", name)
	case strings.IndexByte(name, 0) >= 0:
		return fmt.Errorf("cbfs: file name %q contains NUL", name)
	}
	return nil
}
