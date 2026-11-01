package image

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/linuxboot/fiano/pkg/fmap"
)

// newImage builds a 64 KiB image with an FMAP at 0x100 and the given areas.
func newImage(t *testing.T, areas ...fmap.Area) []byte {
	t.Helper()
	data := bytes.Repeat([]byte{0xff}, 64*1024)
	f := &fmap.FMap{Header: fmap.Header{VerMajor: 1, VerMinor: 1, Size: uint32(len(data))}, Areas: areas}
	copy(f.Signature[:], "__FMAP__")
	f.NAreas = uint16(len(areas))
	if err := fmap.Write(&sliceWriter{buf: data}, f, &fmap.Metadata{Start: 0x100}); err != nil {
		t.Fatal(err)
	}
	return data
}

type sliceWriter struct {
	buf []byte
	off int64
}

func (w *sliceWriter) Write(p []byte) (int, error) {
	n := copy(w.buf[w.off:], p)
	w.off += int64(n)
	return n, nil
}

func (w *sliceWriter) Seek(off int64, whence int) (int64, error) {
	w.off = off
	return off, nil
}

func area(name string, off, size uint32) fmap.Area {
	a := fmap.Area{Offset: off, Size: size}
	copy(a.Name.Value[:], name)
	return a
}

func TestRegions(t *testing.T) {
	data := newImage(t, area("FMAP", 0x100, 0x100), area("RO_VPD", 0x1000, 0x4000), area("SMMSTORE", 0x8000, 0x8000))
	im, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := im.Region("RO_VPD")
	if err != nil || r.Offset != 0x1000 || r.Size != 0x4000 {
		t.Fatalf("RO_VPD = %+v, %v", r, err)
	}
	if im.HasRegion("RW_VPD") {
		t.Error("RW_VPD should not exist")
	}
	b, err := im.RegionData("SMMSTORE")
	if err != nil || len(b) != 0x8000 {
		t.Fatalf("SMMSTORE data len %d, %v", len(b), err)
	}
	b[0] = 0x42
	if im.Data[0x8000] != 0x42 {
		t.Error("RegionData does not alias image data")
	}
	if cap(b) != len(b) {
		t.Error("RegionData slice can grow into the next region")
	}
}

func TestRegionOutsideImage(t *testing.T) {
	data := newImage(t, area("BAD", 0xf000, 0x2000))
	if _, err := Parse(data); err == nil {
		t.Fatal("expected error for region beyond image end")
	}
}

func TestNoFMAP(t *testing.T) {
	if _, err := Parse(bytes.Repeat([]byte{0xff}, 4096)); err == nil {
		t.Fatal("expected error without FMAP")
	}
}

func TestWriteFile(t *testing.T) {
	data := newImage(t, area("RO_VPD", 0x1000, 0x1000))
	im, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "out.rom")
	if err := im.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("written image differs: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("temporary file left behind: %v", entries)
	}
}
