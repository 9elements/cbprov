package cbfs

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/9elements/cbprov/pkg/image"
	"github.com/linuxboot/fiano/pkg/fmap"
)

// anchorMagic is DO_NOT_USE_METADATA_HASH_ANCHOR_MAGIC_DO_NOT_USE from
// commonlib/bsd/metadata_hash.h.
var anchorMagic = []byte("\xadMdtHsh\x15")

// anchorContainer names where cbfstool looks for the anchor of a CBFS: the
// bootblock FMAP region if present, else (primary only) the "bootblock" or
// "apu/amdfw" file in the CBFS itself.
type anchorContainer struct {
	cbfs, bootblock string
	secondary       bool
}

var anchorContainers = []anchorContainer{
	{cbfs: "COREBOOT", bootblock: "BOOTBLOCK"},
	{cbfs: "COREBOOT_B", bootblock: "BOOTBLOCK_B", secondary: true}, // Intel Top Swap
}

// anchor is a struct metadata_hash_anchor inside the image data.
type anchor struct {
	b    []byte // aliases image data from the magic on
	algo hashAlgo
}

func (a *anchor) cbfsHash() []byte { return a.b[12 : 12+a.algo.size()] }
func (a *anchor) fmapHash() []byte { return a.b[12+a.algo.size() : 12+2*a.algo.size()] }

func findAnchor(im *image.Image, c anchorContainer) (*anchor, error) {
	var search []byte
	if im.HasRegion(c.bootblock) {
		b, err := im.RegionData(c.bootblock)
		if err != nil {
			return nil, err
		}
		search = b
	} else {
		if c.secondary || !im.HasRegion(c.cbfs) {
			return nil, nil
		}
		buf, err := im.RegionData(c.cbfs)
		if err != nil {
			return nil, err
		}
		if !hasMagic(buf, 0) {
			return nil, nil
		}
		es, err := walk(buf)
		if err != nil {
			return nil, err
		}
		// cbfs_get_entry() matches names case-insensitively, first hit wins.
		lookup := func(name string, typ uint32) *entry {
			for i := range es {
				if bytes.EqualFold([]byte(es[i].name), []byte(name)) {
					if es[i].typ == typ {
						return &es[i]
					}
					return nil
				}
			}
			return nil
		}
		e := lookup("bootblock", TypeBootblock)
		if e == nil {
			e = lookup("apu/amdfw", TypeAMDFW)
		}
		if e == nil {
			return nil, nil
		}
		search = e.data(buf)
	}
	i := bytes.Index(search, anchorMagic)
	if i < 0 {
		return nil, nil
	}
	b := search[i:]
	if len(b) < 12 {
		return nil, fmt.Errorf("cbfs: truncated metadata hash anchor")
	}
	a := &anchor{b: b, algo: hashAlgo(b[11])}
	if a.algo.size() == 0 {
		return nil, fmt.Errorf("cbfs: unknown CBFS metadata hash algorithm %d", a.algo)
	}
	if len(b) < 12+2*a.algo.size() {
		return nil, fmt.Errorf("cbfs: truncated metadata hash anchor")
	}
	return a, nil
}

// fmapHash hashes the FMAP header and area table, as cbfstool does for the
// anchor's FMAP hash.
func fmapHash(im *image.Image, algo hashAlgo) ([]byte, error) {
	_, md, err := fmap.Read(bytes.NewReader(im.Data))
	if err != nil {
		return nil, err
	}
	const hdrSize, areaSize = 56, 42
	start := md.Start
	if start+hdrSize > uint64(len(im.Data)) {
		return nil, fmt.Errorf("cbfs: FMAP header outside image")
	}
	n := uint64(binary.LittleEndian.Uint16(im.Data[start+hdrSize-2:]))
	end := start + hdrSize + n*areaSize
	if end > uint64(len(im.Data)) {
		return nil, fmt.Errorf("cbfs: FMAP outside image")
	}
	return algo.sum(im.Data[start:end]), nil
}
