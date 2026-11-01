package cbfs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/9elements/cbprov/pkg/image"
)

type testArea struct {
	name      string
	off, size uint32
	flags     uint16
}

// buildFMAP returns a FMAP blob for an image of the given size.
func buildFMAP(size uint32, areas []testArea) []byte {
	var b bytes.Buffer
	b.WriteString("__FMAP__")
	b.Write([]byte{1, 1})
	binary.Write(&b, binary.LittleEndian, uint64(0))
	binary.Write(&b, binary.LittleEndian, size)
	var name [32]byte
	copy(name[:], "FLASH")
	b.Write(name[:])
	binary.Write(&b, binary.LittleEndian, uint16(len(areas)))
	for _, a := range areas {
		binary.Write(&b, binary.LittleEndian, a.off)
		binary.Write(&b, binary.LittleEndian, a.size)
		var n [32]byte
		copy(n[:], a.name)
		b.Write(n[:])
		binary.Write(&b, binary.LittleEndian, a.flags)
	}
	return b.Bytes()
}

const (
	testImageSize = 1 << 20
	testFMAPOff   = 0x1000
	testCBFSOff   = 0x10000
	testCBFSSize  = testImageSize - testCBFSOff
)

var testAreas = []testArea{
	{"RW_MRC_CACHE", 0, 0x1000, 0},
	{"FMAP", testFMAPOff, 0x1000, 0},
	{"SMMSTORE", 0x2000, 0xe000, 0},
	{"COREBOOT", testCBFSOff, testCBFSSize, 0},
}

// newTestImage builds a 1 MiB image whose COREBOOT region holds an empty
// CBFS as cbfstool create makes it.
func newTestImage(t testing.TB) (*image.Image, []byte) {
	t.Helper()
	data := bytes.Repeat([]byte{0xff}, testImageSize)
	fm := buildFMAP(testImageSize, testAreas)
	copy(data[testFMAPOff:], fm)
	writeEmpty(data[testCBFSOff:], 0, testCBFSSize-emptyHeaderLen)
	im, err := image.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return im, fm
}

func mustOpen(t testing.TB, im *image.Image) *FS {
	t.Helper()
	fs, err := Open(im, "COREBOOT")
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// testBlob returns compressible, deterministic data.
func testBlob(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed))
	words := []string{"coreboot ", "payload ", "cbfs ", "LARCHIVE ", "\x00\x00\x00\x00", "romstage ", "0x7fff0000 "}
	var b bytes.Buffer
	for b.Len() < n {
		if r.Intn(8) == 0 {
			b.WriteByte(byte(r.Intn(256)))
		} else {
			b.WriteString(words[r.Intn(len(words))])
		}
	}
	return b.Bytes()[:n]
}

type testSeg struct {
	flags elf.ProgFlag
	typ   elf.ProgType
	paddr uint64
	data  []byte
	memsz uint64
}

// buildELF writes a minimal ELF64 executable with the given program headers.
func buildELF(machine elf.Machine, entry uint64, segs []testSeg) []byte {
	const ehSize, phSize = 64, 56
	off := uint64(ehSize + phSize*len(segs))
	var phdrs, body bytes.Buffer
	for _, s := range segs {
		p := elf.Prog64{Type: uint32(s.typ), Flags: uint32(s.flags), Off: off + uint64(body.Len()),
			Vaddr: s.paddr, Paddr: s.paddr, Filesz: uint64(len(s.data)), Memsz: s.memsz, Align: 16}
		binary.Write(&phdrs, binary.LittleEndian, p)
		body.Write(s.data)
	}
	h := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: 1, Entry: entry,
		Phoff: ehSize, Ehsize: ehSize, Phentsize: phSize, Phnum: uint16(len(segs)), Shentsize: 64}
	copy(h.Ident[:], elf.ELFMAG)
	h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, h)
	out.Write(phdrs.Bytes())
	out.Write(body.Bytes())
	return out.Bytes()
}

func testELF() []byte {
	return buildELF(elf.EM_X86_64, 0x100010, []testSeg{
		{typ: elf.PT_LOAD, flags: elf.PF_R | elf.PF_X, paddr: 0x100000, data: testBlob(1, 40000), memsz: 40000},
		{typ: elf.PT_NOTE, flags: elf.PF_R, paddr: 0, data: []byte("note"), memsz: 4},
		{typ: elf.PT_LOAD, flags: elf.PF_R | elf.PF_W, paddr: 0x110000, data: testBlob(2, 3000), memsz: 5000},
		{typ: elf.PT_LOAD, flags: elf.PF_R | elf.PF_W, paddr: 0x120000, memsz: 0x2000},
		{typ: elf.PT_LOAD, flags: elf.PF_R, paddr: 0x130000},
	})
}

// testBootblock returns a fake bootblock carrying a metadata hash anchor.
func testBootblock(algo hashAlgo) []byte {
	bb := bytes.Repeat([]byte{0x90}, 4096)
	a := append([]byte{}, anchorMagic...)
	a = append(a, 0, 0, 0, byte(algo))
	a = append(a, make([]byte, 2*64)...)
	copy(bb[1024:], a)
	return bb
}
