package provision

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/linuxboot/fiano/pkg/fmap"

	"github.com/9elements/cbprov/pkg/buildconfig"
	"github.com/9elements/cbprov/pkg/cbfs"
	"github.com/9elements/cbprov/pkg/efivars"
	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/options"
	"github.com/9elements/cbprov/pkg/vpd"
)

type sliceWriter struct {
	buf []byte
	off int64
}

func (w *sliceWriter) Write(p []byte) (int, error) {
	n := copy(w.buf[w.off:], p)
	w.off += int64(n)
	return n, nil
}

func (w *sliceWriter) Seek(off int64, _ int) (int64, error) { w.off = off; return off, nil }

type testArea struct {
	name      string
	off, size uint32
}

func buildImage(t *testing.T, size int, areas []testArea) *image.Image {
	t.Helper()
	data := bytes.Repeat([]byte{0xff}, size)
	f := &fmap.FMap{Header: fmap.Header{VerMajor: 1, VerMinor: 1, Size: uint32(len(data)), NAreas: uint16(len(areas))}}
	copy(f.Signature[:], "__FMAP__")
	for _, a := range areas {
		ar := fmap.Area{Offset: a.off, Size: a.size}
		copy(ar.Name.Value[:], a.name)
		f.Areas = append(f.Areas, ar)
	}
	if err := fmap.Write(&sliceWriter{buf: data}, f, &fmap.Metadata{Start: 0}); err != nil {
		t.Fatal(err)
	}
	im, err := image.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return im
}

// testImage has an FMAP, RO_VPD and an erased SMMSTORE but no CBFS.
func testImage(t *testing.T) *image.Image {
	return buildImage(t, 512*1024, []testArea{{"FMAP", 0x0, 0x1000}, {"RO_VPD", 0x4000, 0x4000}, {"SMMSTORE", 0x40000, 0x40000}})
}

// abImage is laid out like an AMD PSP A/B image: two RO CBFS whose metadata
// hash anchors sit in separate BOOTBLOCK regions. config is the CBFS build config.
func abImage(t *testing.T, config string) *image.Image {
	t.Helper()
	im := buildImage(t, 1<<20, []testArea{{"FMAP", 0x0, 0x1000}, {"BOOTBLOCK", 0x1000, 0x1000},
		{"BOOTBLOCK_B", 0x2000, 0x1000}, {"SMMSTORE", 0x40000, 0x40000},
		{"COREBOOT", 0x80000, 0x40000}, {"COREBOOT_B", 0xc0000, 0x40000}})
	for _, bb := range []string{"BOOTBLOCK", "BOOTBLOCK_B"} {
		b, _ := im.RegionData(bb)
		copy(b[0x100:], append([]byte("\xadMdtHsh\x15\x00\x00\x00\x02"), make([]byte, 64)...)) // SHA-256 anchor
	}
	for _, region := range []string{"COREBOOT", "COREBOOT_B"} {
		b, _ := im.RegionData(region)
		// Empty CBFS as cbfstool creates it: one null file spanning the region.
		copy(b, "LARCHIVE")
		binary.BigEndian.PutUint32(b[8:], uint32(len(b)-28))
		binary.BigEndian.PutUint32(b[12:], 0xffffffff)
		binary.BigEndian.PutUint32(b[16:], 0)
		binary.BigEndian.PutUint32(b[20:], 28)
		clear(b[24:28])
		fs, err := cbfs.Open(im, region)
		if err != nil {
			t.Fatal(err)
		}
		if err := fs.AddRaw(buildconfig.FileName, []byte(config), cbfs.CompressNone); err != nil {
			t.Fatal(err)
		}
		if err := fs.AddPayloadFlat("fallback/payload", []byte("old payload"), 0x100000, 0x100000, cbfs.CompressNone); err != nil {
			t.Fatal(err)
		}
	}
	return im
}

func TestSetVPD(t *testing.T) {
	im := testImage(t)
	w, err := SetVPD(im, "RO_VPD", []KV{
		{"serial_number", "SN123"},
		{"system_uuid", "00112233-4455-6677-8899-aabbccddeeff"},
		{"custom_key", "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 1 {
		t.Errorf("warnings = %q, want one for custom_key", w)
	}
	st, _, err := OpenVPD(im, "RO_VPD")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := st.Get("serial_number"); string(v) != "SN123" {
		t.Errorf("serial_number = %q", v)
	}
	if v, _ := st.Get("system_uuid"); !bytes.Equal(v, []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("system_uuid = % x", v)
	}
	if err := DeleteVPD(im, "RO_VPD", []string{"custom_key"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteVPD(im, "RO_VPD", []string{"custom_key"}); err == nil {
		t.Error("deleting a missing key should fail")
	}
	if _, err := SetVPD(im, "RO_VPD", []KV{{"system_uuid", "nope"}}); err == nil {
		t.Error("invalid UUID accepted")
	}
}

func TestApply(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(spec, []byte(`
vpd:
  serial_number: SN1
  mlb_serial_number: MLB1
options:
  boot_delay: 3
`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.VPD) != 2 || s.VPD[0].Key != "serial_number" || s.VPD[1].Key != "mlb_serial_number" {
		t.Fatalf("vpd order lost: %+v", s.VPD)
	}
	im := testImage(t)
	w, err := Apply(im, s, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) == 0 {
		t.Error("expected a raw-mode warning")
	}
	st, _, _ := OpenVPD(im, "RO_VPD")
	if v, _ := st.Get("mlb_serial_number"); string(v) != "MLB1" {
		t.Errorf("mlb_serial_number = %q", v)
	}
	region, _ := im.RegionData(options.Region)
	es, err := efivars.Parse(region)
	if err != nil {
		t.Fatalf("SMMSTORE not initialised: %v", err)
	}
	if v, ok := es.Get(efivars.CorebootNvDataGUID, "boot_delay"); !ok || !bytes.Equal(v.Data, []byte{3, 0, 0, 0}) {
		t.Errorf("boot_delay = %+v", v)
	}
}

func TestLoadSpecRejectsUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(p, []byte("vdp:\n  serial_number: x\n"), 0o644)
	if _, err := LoadSpec(p); err == nil {
		t.Error("typo 'vdp' accepted")
	}
}

func TestResetList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(p, []byte("options_reset: all\n"), 0o644)
	s, err := LoadSpec(p)
	if err != nil || !s.OptionsReset.All {
		t.Fatalf("all: %+v %v", s, err)
	}
	os.WriteFile(p, []byte("options_reset: [a, b]\n"), 0o644)
	s, err = LoadSpec(p)
	if err != nil || len(s.OptionsReset.Names) != 2 {
		t.Fatalf("list: %+v %v", s, err)
	}
}

func TestVPDOverflow(t *testing.T) {
	im := testImage(t)
	big := bytes.Repeat([]byte("A"), 0x4000)
	st, data, _ := OpenVPD(im, "RO_VPD")
	if err := st.Set("blob", big); err != nil {
		t.Fatal(err)
	}
	if err := writeVPD(st, data); err == nil {
		t.Error("oversized VPD accepted")
	}
	if !vpdErased(data) {
		t.Error("region changed despite error")
	}
}

func vpdErased(b []byte) bool {
	_, err := vpd.Decode(b)
	return err == nil && bytes.Count(b, []byte{0xff}) == len(b)
}

func TestReplacePayloadAB(t *testing.T) {
	im := abImage(t, "CONFIG_PSP_AB_RECOVERY=y\n")
	orig := bytes.Clone(im.Data)
	payload := bytes.Repeat([]byte("new payload "), 1000)
	if _, err := ReplacePayload(im, PayloadSpec{Data: payload, Flat: true, LoadAddr: 0x200000, Entry: 0x200000}); err != nil {
		t.Fatal(err)
	}
	for _, region := range []string{"COREBOOT", "COREBOOT_B"} {
		fs, _ := cbfs.Open(im, region)
		f, found, err := findFile(fs, "fallback/payload")
		if err != nil || !found || len(f.Segments) == 0 || f.Segments[0].LoadAddr != 0x200000 {
			t.Errorf("%s: payload not replaced: %+v %v", region, f, err)
		}
	}
	var allowed []image.Region
	for _, n := range CBFSRegions {
		r, _ := im.Region(n)
		allowed = append(allowed, r)
	}
	for i := range orig {
		if orig[i] == im.Data[i] {
			continue
		}
		inside := false
		for _, r := range allowed {
			inside = inside || (uint32(i) >= r.Offset && uint32(i) < r.Offset+r.Size)
		}
		if !inside {
			t.Fatalf("byte 0x%x outside %v changed", i, CBFSRegions)
		}
	}
	for _, bb := range []string{"BOOTBLOCK", "BOOTBLOCK_B"} {
		r, _ := im.Region(bb)
		if bytes.Equal(orig[r.Offset:r.Offset+r.Size], im.Data[r.Offset:r.Offset+r.Size]) {
			t.Errorf("%s: metadata hash not updated", bb)
		}
	}
	check, err := image.Parse(bytes.Clone(im.Data))
	if err != nil {
		t.Fatal(err)
	}
	if err := cbfs.UpdateMetadataHash(check); err != nil || !bytes.Equal(check.Data, im.Data) {
		t.Errorf("metadata hashes stale after replace (%v)", err)
	}
}
