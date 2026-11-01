package cbfs

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	inputs := map[string][]byte{
		"empty1": {0x42},
		"short":  []byte("abcabcabcabcabcabcabc"),
		"zeros":  make([]byte, 100000),
		"text":   testBlob(7, 300000),
		"random": func() []byte {
			b := testBlob(3, 70000)
			for i := range b {
				b[i] ^= byte(i * 7919 >> 3)
			}
			return b
		}(),
		"big": bytes.Repeat(testBlob(9, 5000), 1000), // > one 4 MiB LZ4 block
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			c := lzmaCompress(in)
			out, err := lzmaDecompress(c, uint64(len(in)))
			if err != nil || !bytes.Equal(out, in) {
				t.Fatalf("lzma round trip failed: %v", err)
			}
			c4 := lz4Compress(in)
			out, err = lz4Decompress(c4, uint64(len(in)))
			if err != nil || !bytes.Equal(out, in) {
				t.Fatalf("lz4 round trip failed: %v", err)
			}
			if name == "text" && (len(c) > len(in)/3 || len(c4) > len(in)/2) {
				t.Errorf("poor ratio: lzma %d lz4 %d of %d", len(c), len(c4), len(in))
			}
		})
	}
}

func TestXXH32(t *testing.T) {
	for in, want := range map[string]uint32{"": 0x02CC5D05, "abc": 0x32D153FF,
		"Nobody inspects the spammish repetition": 0xE2293B2F} {
		if got := xxh32([]byte(in), 0); got != want {
			t.Errorf("xxh32(%q) = %08x, want %08x", in, got, want)
		}
	}
}

func TestAddListExtractRemove(t *testing.T) {
	im, _ := newTestImage(t)
	fs := mustOpen(t, im)
	free0, err := fs.Free()
	if err != nil || free0 != testCBFSSize-emptyHeaderLen {
		t.Fatalf("Free = %d, %v", free0, err)
	}
	blobs := map[string][]byte{"a": testBlob(1, 1000), "b": testBlob(2, 50000), "c": testBlob(3, 7000)}
	comps := map[string]Compression{"a": CompressNone, "b": CompressLZMA, "c": CompressLZ4}
	for _, n := range []string{"a", "b", "c"} {
		if err := fs.AddRaw(n, blobs[n], comps[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := fs.AddRaw("a", []byte("x"), CompressNone); err == nil {
		t.Error("duplicate name accepted")
	}
	files, err := fs.Files()
	if err != nil || len(files) != 3 {
		t.Fatalf("Files = %v, %v", files, err)
	}
	if files[0].Offset != 0 || files[1].Offset != 0x440 {
		t.Errorf("offsets %#x %#x", files[0].Offset, files[1].Offset)
	}
	for _, f := range files {
		if f.Compression != comps[f.Name] {
			t.Errorf("%s: compression %v", f.Name, f.Compression)
		}
		if f.Compression != CompressNone && f.DecompSize != uint32(len(blobs[f.Name])) {
			t.Errorf("%s: decompressed size %d", f.Name, f.DecompSize)
		}
		got, err := fs.Extract(f.Name)
		if err != nil || !bytes.Equal(got, blobs[f.Name]) {
			t.Errorf("Extract(%s): %v", f.Name, err)
		}
	}
	if err := fs.Remove("b"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Extract("b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Extract removed file: %v", err)
	}
	// Removing everything merges back into one empty file spanning the region.
	for _, n := range []string{"a", "c"} {
		if err := fs.Remove(n); err != nil {
			t.Fatal(err)
		}
	}
	es, _ := walk(im.Data[testCBFSOff:])
	if len(es) != 1 || es[0].typ != TypeNull || es[0].len != testCBFSSize-emptyHeaderLen {
		t.Errorf("not merged: %+v", es)
	}
}

func TestNoSpace(t *testing.T) {
	im, _ := newTestImage(t)
	fs := mustOpen(t, im)
	before := bytes.Clone(im.Data)
	if err := fs.AddRaw("huge", make([]byte, testCBFSSize), CompressNone); err == nil {
		t.Fatal("oversized file accepted")
	}
	if !bytes.Equal(before, im.Data) {
		t.Error("failed add modified the image")
	}
	free, _ := fs.Free()
	if err := fs.AddRaw("fits", make([]byte, free-64), CompressNone); err != nil {
		t.Fatal(err)
	}
}

func TestHashAttributePropagates(t *testing.T) {
	im, _ := newTestImage(t)
	fs := mustOpen(t, im)
	// A file with a hash attribute, as cbfstool add -A sha256 writes it.
	data := []byte("hashed")
	hdr, err := fileHeader("pre", TypeRaw, uint32(len(data)), [][]byte{hashAttr(2, data)})
	if err != nil {
		t.Fatal(err)
	}
	buf := im.Data[testCBFSOff:]
	copy(buf, hdr)
	copy(buf[len(hdr):], data)
	writeEmpty(buf, 0x40*2, testCBFSSize-0x80-emptyHeaderLen)
	if err := fs.AddRaw("new", testBlob(4, 2000), CompressLZMA); err != nil {
		t.Fatal(err)
	}
	es, _ := walk(buf)
	e := find(es, "new")
	algo, sum := e.fileHash(buf)
	want := sha256.Sum256(e.data(buf))
	if algo != 2 || !bytes.Equal(sum, want[:]) {
		t.Errorf("hash attribute %d %x", algo, sum)
	}
	if c, _ := e.compression(buf); c != CompressLZMA {
		t.Errorf("compression attribute lost")
	}
}

func TestMetadataHashAnchor(t *testing.T) {
	im, fm := newTestImage(t)
	fs := mustOpen(t, im)
	v, err := DetectVerification(im)
	if err != nil || v.MetadataHash || v.Vboot {
		t.Fatalf("plain image: %+v %v", v, err)
	}
	buf := im.Data[testCBFSOff:]
	// Put the bootblock as the last file like cbfstool does on x86.
	bb := testBootblock(2)
	hdr, _ := fileHeader("bootblock", TypeBootblock, uint32(len(bb)), nil)
	bbOff := uint32(testCBFSSize - len(bb) - 64)
	copy(buf[bbOff:], hdr)
	copy(buf[bbOff+64:], bb)
	be.PutUint32(buf[bbOff+20:], 64)
	writeEmpty(buf, 0, bbOff-emptyHeaderLen)
	if v, err = DetectVerification(im); err != nil || !v.MetadataHash {
		t.Fatalf("anchor not found: %+v %v", v, err)
	}
	if err := fs.AddRaw("cfr", testBlob(5, 3000), CompressLZMA); err != nil {
		t.Fatal(err)
	}
	a, err := findAnchor(im, anchorContainers[0])
	if err != nil || a == nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.cbfsHash(), metadataHash(buf, 2)) {
		t.Error("metadata hash not updated after add")
	}
	want := sha256.Sum256(fm)
	if !bytes.Equal(a.fmapHash(), want[:]) {
		t.Error("FMAP hash not set")
	}
	es, _ := walk(buf)
	if algo, _ := find(es, "cfr").fileHash(buf); algo != 2 {
		t.Error("new file has no hash attribute")
	}
	old := bytes.Clone(a.cbfsHash())
	if err := fs.Remove("cfr"); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(old, a.cbfsHash()) || !bytes.Equal(a.cbfsHash(), metadataHash(buf, 2)) {
		t.Error("metadata hash not updated after remove")
	}
	files, _ := fs.Files()
	if len(files) != 1 || files[0].Name != "bootblock" || files[0].Offset != bbOff {
		t.Errorf("files %+v", files)
	}
}

func TestPayloadELF(t *testing.T) {
	raw := testELF()
	for _, comp := range []Compression{CompressNone, CompressLZMA, CompressLZ4} {
		im, _ := newTestImage(t)
		fs := mustOpen(t, im)
		if err := fs.AddPayloadELF("fallback/payload", raw, comp); err != nil {
			t.Fatal(err)
		}
		files, _ := fs.Files()
		segs := files[0].Segments
		wantTypes := []uint32{SegCode, SegData, SegBSS, SegEntry}
		if len(segs) != len(wantTypes) {
			t.Fatalf("%v: segments %+v", comp, segs)
		}
		self, _ := fs.Extract("fallback/payload")
		f, _ := elf.NewFile(bytes.NewReader(raw))
		var loads []*elf.Prog
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Memsz > 0 {
				loads = append(loads, p)
			}
		}
		for i, s := range segs {
			if s.Type != wantTypes[i] {
				t.Errorf("%v: segment %d type %08x", comp, i, s.Type)
			}
			if s.Type == SegEntry {
				if s.LoadAddr != 0x100010 {
					t.Errorf("entry %#x", s.LoadAddr)
				}
				continue
			}
			p := loads[i]
			if s.LoadAddr != p.Paddr || uint64(s.MemLen) != p.Memsz {
				t.Errorf("%v: segment %d addr %#x memlen %d", comp, i, s.LoadAddr, s.MemLen)
			}
			if s.Type == SegBSS {
				continue
			}
			if comp != CompressNone && s.Compression != comp {
				t.Errorf("%v: segment %d not compressed", comp, i)
			}
			got, err := decompress(self[s.Offset:s.Offset+s.Len], s.Compression, uint32(p.Filesz))
			want := raw[p.Off : p.Off+p.Filesz]
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("%v: segment %d data mismatch: %v", comp, i, err)
			}
		}
	}
	im, _ := newTestImage(t)
	arm := buildELF(elf.EM_PPC64, 0, []testSeg{{typ: elf.PT_LOAD, flags: elf.PF_X, data: []byte{1}, memsz: 1}})
	if err := mustOpen(t, im).AddPayloadELF("p", arm, CompressNone); err == nil {
		t.Error("unsupported machine accepted")
	}
}

func TestPayloadFlat(t *testing.T) {
	im, _ := newTestImage(t)
	fs := mustOpen(t, im)
	bin := testBlob(6, 20000)
	if err := fs.AddPayloadFlat("img/flat", bin, 0x800000, 0x800100, CompressLZ4); err != nil {
		t.Fatal(err)
	}
	files, _ := fs.Files()
	s := files[0].Segments
	if len(s) != 2 || s[0].Type != SegCode || s[0].LoadAddr != 0x800000 || s[0].MemLen != 20000 ||
		s[0].Compression != CompressLZ4 || s[0].Offset != 56 || s[1].Type != SegEntry || s[1].LoadAddr != 0x800100 {
		t.Fatalf("segments %+v", s)
	}
	self, _ := fs.Extract("img/flat")
	got, err := decompress(self[56:56+s[0].Len], CompressLZ4, 20000)
	if err != nil || !bytes.Equal(got, bin) {
		t.Errorf("flat payload data: %v", err)
	}
}

func TestOpenRejectsNonCBFS(t *testing.T) {
	im, _ := newTestImage(t)
	if _, err := Open(im, "SMMSTORE"); err == nil {
		t.Error("non-CBFS region opened")
	}
	if _, err := Open(im, "NOPE"); err == nil {
		t.Error("missing region opened")
	}
}
