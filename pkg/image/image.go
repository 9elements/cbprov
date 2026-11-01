// Package image loads a coreboot ROM image and gives access to its FMAP regions.
package image

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/linuxboot/fiano/pkg/fmap"
)

// Region is one FMAP area.
type Region struct {
	Name   string
	Offset uint32
	Size   uint32
	Flags  uint16
}

// Image is a coreboot ROM held in memory. Region data returned by RegionData
// aliases Data, so edits to it change the image.
type Image struct {
	Data []byte
	FMAP *fmap.FMap
}

// Open reads a ROM image from disk.
func Open(path string) (*Image, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses a ROM image held in memory. The image keeps a reference to data.
func Parse(data []byte) (*Image, error) {
	f, _, err := fmap.Read(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("no FMAP found: %w", err)
	}
	if uint64(f.Size) > uint64(len(data)) {
		return nil, fmt.Errorf("FMAP size 0x%x exceeds image size 0x%x", f.Size, len(data))
	}
	im := &Image{Data: data, FMAP: f}
	for _, r := range im.Regions() {
		if uint64(r.Offset)+uint64(r.Size) > uint64(len(data)) {
			return nil, fmt.Errorf("FMAP region %s (0x%x+0x%x) outside image", r.Name, r.Offset, r.Size)
		}
	}
	return im, nil
}

// Regions lists all FMAP areas in FMAP order.
func (im *Image) Regions() []Region {
	rs := make([]Region, 0, len(im.FMAP.Areas))
	for i := range im.FMAP.Areas {
		a := &im.FMAP.Areas[i]
		rs = append(rs, Region{Name: a.Name.String(), Offset: a.Offset, Size: a.Size, Flags: a.Flags})
	}
	return rs
}

// Region looks up an FMAP area by name.
func (im *Image) Region(name string) (Region, error) {
	for _, r := range im.Regions() {
		if r.Name == name {
			return r, nil
		}
	}
	return Region{}, fmt.Errorf("FMAP region %s not found", name)
}

// HasRegion reports whether the FMAP has an area with that name.
func (im *Image) HasRegion(name string) bool {
	_, err := im.Region(name)
	return err == nil
}

// RegionData returns the bytes of an FMAP area, aliasing im.Data.
func (im *Image) RegionData(name string) ([]byte, error) {
	r, err := im.Region(name)
	if err != nil {
		return nil, err
	}
	return im.Data[r.Offset : r.Offset+r.Size : r.Offset+r.Size], nil
}

// WriteFile writes the image atomically: to a temporary file in the target
// directory, then renamed over path.
func (im *Image) WriteFile(path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(im.Data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
