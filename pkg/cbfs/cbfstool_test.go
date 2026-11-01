package cbfs

// Differential tests against coreboot's cbfstool. They run only when
// CBPROV_CBFSTOOL points to a cbfstool binary; TestCbfstoolFixtures also needs
// CBPROV_FIXTURES, a directory of <name>/coreboot.rom images.

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/9elements/cbprov/pkg/image"
)

func cbfstoolPath(t *testing.T) string {
	p := os.Getenv("CBPROV_CBFSTOOL")
	if p == "" {
		t.Skip("CBPROV_CBFSTOOL not set")
	}
	return p
}

func runCbfstool(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(cbfstoolPath(t), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cbfstool %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

type printed struct {
	files      []File
	hashesOK   bool   // every printed file hash is valid
	verifyLine string // [CBFS VERIFICATION (...)] state, if printed
	mdHash     string // [METADATA HASH] value incl. :valid/:invalid
}

var compByName = map[string]Compression{"LZMA": CompressLZMA, "LZ4": CompressLZ4, "ZSTD": CompressZSTD}

// cbfstoolPrint parses "cbfstool print -k -v".
func cbfstoolPrint(t *testing.T, rom, region string) printed {
	t.Helper()
	p := printed{hashesOK: true}
	for _, line := range strings.Split(runCbfstool(t, rom, "print", "-k", "-v", "-r", region), "\n") {
		f := strings.Split(line, "\t")
		switch {
		case strings.HasPrefix(line, "[CBFS VERIFICATION"):
			p.verifyLine = f[1]
			continue
		case strings.HasPrefix(line, "[METADATA HASH]"):
			p.mdHash = f[1]
			continue
		case len(f) < 6 || f[0] == "Name" || strings.HasPrefix(line, "["):
			continue
		case f[2] == "null" || f[2] == "deleted":
			continue
		}
		off, _ := strconv.ParseUint(f[1], 0, 32)
		size, _ := strconv.ParseUint(f[4], 0, 32)
		file := File{Name: f[0], Offset: uint32(off), TypeName: f[2], Size: uint32(size)}
		for _, kv := range f[6:] {
			parts := strings.Split(kv, ":")
			switch parts[0] {
			case "comp":
				file.Compression = compByName[parts[1]]
				d, _ := strconv.ParseUint(parts[2], 0, 32)
				file.DecompSize = uint32(d)
			case "hash":
				p.hashesOK = p.hashesOK && parts[len(parts)-1] == "valid"
			}
		}
		p.files = append(p.files, file)
	}
	return p
}

func compareFiles(t *testing.T, ours []File, theirs []File) {
	t.Helper()
	if len(ours) != len(theirs) {
		t.Fatalf("file count: ours %d, cbfstool %d", len(ours), len(theirs))
	}
	for i := range ours {
		o, c := ours[i], theirs[i]
		if o.Name != c.Name || o.Offset != c.Offset || o.TypeName != c.TypeName || o.Size != c.Size ||
			o.Compression != c.Compression || o.DecompSize != c.DecompSize {
			t.Errorf("file %d: ours %+v, cbfstool %+v", i, o, c)
		}
	}
}

func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseImage(t *testing.T, data []byte) *image.Image {
	t.Helper()
	im, err := image.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return im
}

var compArg = map[Compression]string{CompressNone: "none", CompressLZMA: "lzma", CompressLZ4: "lz4"}

// TestCbfstoolSynthetic replays the same edits with cbfstool and with this
// package on a fresh CBFS_VERIFICATION image and requires identical bytes
// where compression is not involved.
func TestCbfstoolSynthetic(t *testing.T) {
	cbfstoolPath(t)
	dir := t.TempDir()
	ref, fm := newTestImage(t)
	rom := filepath.Join(dir, "ref.rom")
	runCbfstool(t, rom, "create", "-M", writeTemp(t, dir, "fmap.bin", fm))
	if !bytes.Equal(readFile(t, rom), ref.Data) {
		t.Fatal("cbfstool create differs from the test image builder")
	}
	bb := testBootblock(2)
	bbOff := testCBFSSize - len(bb)
	runCbfstool(t, rom, "add", "-f", writeTemp(t, dir, "bb.bin", bb), "-n", "bootblock", "-t", "bootblock",
		"-b", fmt.Sprint(bbOff))

	im := parseImage(t, readFile(t, rom))
	fs := mustOpen(t, im)
	if v, err := DetectVerification(im); err != nil || !v.MetadataHash {
		t.Fatalf("anchor not detected: %+v %v", v, err)
	}
	elfPath := writeTemp(t, dir, "payload.elf", testELF())
	flat := testBlob(11, 30000)
	flatPath := writeTemp(t, dir, "flat.bin", flat)
	step := func(name string, ours func() error, theirs ...string) {
		t.Helper()
		if err := ours(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		runCbfstool(t, append([]string{rom}, theirs...)...)
		if !bytes.Equal(readFile(t, rom), im.Data) {
			t.Fatalf("%s: image differs from cbfstool", name)
		}
	}
	blob := func(seed int64, n int) (string, []byte) {
		b := testBlob(seed, n)
		return writeTemp(t, dir, fmt.Sprintf("blob%d", seed), b), b
	}
	pa, a := blob(1, 1000)
	pb, b := blob(2, 70000)
	pc, c := blob(3, 500)
	step("add a", func() error { return fs.AddRaw("a", a, CompressNone) }, "add", "-f", pa, "-n", "a", "-t", "raw")
	step("add b", func() error { return fs.AddRaw("b", b, CompressNone) }, "add", "-f", pb, "-n", "b", "-t", "raw")
	step("add payload", func() error { return fs.AddPayloadELF("fallback/payload", testELF(), CompressNone) },
		"add-payload", "-f", elfPath, "-n", "fallback/payload", "-c", "none")
	step("remove a", func() error { return fs.Remove("a") }, "remove", "-n", "a")
	step("add c", func() error { return fs.AddRaw("c", c, CompressNone) }, "add", "-f", pc, "-n", "c", "-t", "raw")
	step("remove b", func() error { return fs.Remove("b") }, "remove", "-n", "b")
	step("add flat", func() error { return fs.AddPayloadFlat("img/flat", flat, 0x800000, 0x800010, CompressNone) },
		"add-flat-binary", "-f", flatPath, "-n", "img/flat", "-l", "0x800000", "-e", "0x800010", "-c", "none")
	step("remove payload", func() error { return fs.Remove("fallback/payload") }, "remove", "-n", "fallback/payload")

	// Compressed adds: cbfstool's encoders differ, so check that cbfstool
	// reads ours back and that the verification state stays valid.
	for _, comp := range []Compression{CompressLZMA, CompressLZ4} {
		n := "raw-" + compArg[comp]
		if err := fs.AddRaw(n, b, comp); err != nil {
			t.Fatal(err)
		}
		pn := "payload-" + compArg[comp]
		if err := fs.AddPayloadELF(pn, testELF(), comp); err != nil {
			t.Fatal(err)
		}
		if err := fs.AddPayloadFlat("flat-"+compArg[comp], flat, 0x800000, 0x800010, comp); err != nil {
			t.Fatal(err)
		}
	}
	ours := writeTemp(t, dir, "ours.rom", im.Data)
	p := cbfstoolPrint(t, ours, "COREBOOT")
	files, _ := fs.Files()
	compareFiles(t, files, p.files)
	if !p.hashesOK || p.verifyLine != "fully valid" || !strings.HasSuffix(p.mdHash, ":valid") {
		t.Errorf("cbfstool verification: hashes %v, %q, %q", p.hashesOK, p.verifyLine, p.mdHash)
	}
	for _, comp := range []Compression{CompressLZMA, CompressLZ4} {
		out := filepath.Join(dir, "x")
		runCbfstool(t, ours, "extract", "-n", "raw-"+compArg[comp], "-f", out)
		if !bytes.Equal(readFile(t, out), b) {
			t.Errorf("cbfstool extract of %s raw differs", comp)
		}
		// cbfstool turns the SELF back into an ELF, decompressing each segment.
		runCbfstool(t, ours, "extract", "-m", "x86", "-n", "payload-"+compArg[comp], "-f", out)
		mine := readFile(t, out)
		runCbfstool(t, rom, "add-payload", "-f", elfPath, "-n", "ref-"+compArg[comp], "-c", compArg[comp])
		runCbfstool(t, rom, "extract", "-m", "x86", "-n", "ref-"+compArg[comp], "-f", out)
		if !sameLoad(t, mine, readFile(t, out)) {
			t.Errorf("%s payload: cbfstool's ELF export differs from its own add-payload", comp)
		}
		runCbfstool(t, ours, "extract", "-m", "x86", "-n", "flat-"+compArg[comp], "-f", out)
		mine = readFile(t, out)
		runCbfstool(t, rom, "add-flat-binary", "-f", flatPath, "-n", "rflat-"+compArg[comp], "-l", "0x800000",
			"-e", "0x800010", "-c", compArg[comp])
		runCbfstool(t, rom, "extract", "-m", "x86", "-n", "rflat-"+compArg[comp], "-f", out)
		if !sameLoad(t, mine, readFile(t, out)) {
			t.Errorf("%s flat payload: ELF export differs", comp)
		}
	}
	for _, f := range files {
		ex, err := fs.Extract(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		args := []string{ours, "extract", "-n", f.Name, "-f", filepath.Join(dir, "x")}
		if f.Type == TypeSELF {
			args = append(args, "-U")
		}
		runCbfstool(t, args...)
		if !bytes.Equal(ex, readFile(t, filepath.Join(dir, "x"))) {
			t.Errorf("Extract(%s) differs from cbfstool extract", f.Name)
		}
	}
}

// TestCbfstoolHashedNoAnchor checks hash attribute propagation for CBFSes
// whose files carry hashes without a metadata anchor (cbfstool add -A).
func TestCbfstoolHashedNoAnchor(t *testing.T) {
	cbfstoolPath(t)
	dir := t.TempDir()
	_, fm := newTestImage(t)
	rom := filepath.Join(dir, "ref.rom")
	runCbfstool(t, rom, "create", "-M", writeTemp(t, dir, "fmap.bin", fm))
	pa := writeTemp(t, dir, "a", testBlob(1, 3000))
	runCbfstool(t, rom, "add", "-f", pa, "-n", "a", "-t", "raw", "-A", "sha512")
	im := parseImage(t, readFile(t, rom))
	b := testBlob(2, 5000)
	if err := mustOpen(t, im).AddRaw("b", b, CompressNone); err != nil {
		t.Fatal(err)
	}
	runCbfstool(t, rom, "add", "-f", writeTemp(t, dir, "b", b), "-n", "b", "-t", "raw", "-A", "sha512")
	if !bytes.Equal(readFile(t, rom), im.Data) {
		t.Fatal("image differs from cbfstool add -A sha512")
	}
}

var cbfsArch = map[uint32]string{archX86: "x86", archAArch64: "arm64", archRISCV: "riscv", archARM: "arm"}

// TestCbfstoolFixtures compares listing and extraction on real images and
// replays a payload swap with both tools.
func TestCbfstoolFixtures(t *testing.T) {
	cbfstoolPath(t)
	root := os.Getenv("CBPROV_FIXTURES")
	if root == "" {
		t.Skip("CBPROV_FIXTURES not set")
	}
	roms, _ := filepath.Glob(filepath.Join(root, "*", "coreboot.rom"))
	if len(roms) == 0 {
		t.Skipf("no fixtures in %s", root)
	}
	for _, romPath := range roms {
		t.Run(filepath.Base(filepath.Dir(romPath)), func(t *testing.T) {
			dir := t.TempDir()
			data := readFile(t, romPath)
			im := parseImage(t, bytes.Clone(data))
			for _, region := range []string{"COREBOOT", "FW_MAIN_A", "FW_MAIN_B"} {
				if !im.HasRegion(region) {
					continue
				}
				fs, err := Open(im, region)
				if err != nil {
					t.Logf("%s: %v", region, err)
					continue
				}
				files, err := fs.Files()
				if err != nil {
					t.Fatal(err)
				}
				compareFiles(t, files, cbfstoolPrint(t, romPath, region).files)
				for _, f := range files {
					if f.Type == 0x10 || f.Type == 0x11 || f.Compression == CompressZSTD {
						continue // stages are exported as ELF by cbfstool
					}
					ex, err := fs.Extract(f.Name)
					if err != nil {
						t.Errorf("%s/%s: %v", region, f.Name, err)
						continue
					}
					out := filepath.Join(dir, "x")
					args := []string{romPath, "extract", "-r", region, "-n", f.Name, "-f", out}
					if f.Type == TypeSELF || f.Type == 0x21 {
						args = append(args, "-U")
					}
					runCbfstool(t, args...)
					if !bytes.Equal(ex, readFile(t, out)) {
						t.Errorf("%s/%s: Extract differs from cbfstool", region, f.Name)
					}
				}
			}
			fixtureRawEdits(t, data, dir)
			fixturePayloadSwap(t, romPath, data, dir)
		})
	}
}

// fixtureRawEdits adds and removes a raw file in every CBFS region with both
// tools and requires identical images (placement, hash attributes, metadata hash).
func fixtureRawEdits(t *testing.T, data []byte, dir string) {
	im := parseImage(t, bytes.Clone(data))
	// On an untouched image recomputing both anchor hashes must change nothing.
	if err := UpdateMetadataHash(im); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(im.Data, data) {
		t.Fatal("UpdateMetadataHash changed a pristine image")
	}
	ref := writeTemp(t, dir, "ref.rom", data)
	blob := testBlob(42, 3000)
	blobPath := writeTemp(t, dir, "blob", blob)
	for _, region := range []string{"COREBOOT", "FW_MAIN_A", "FW_MAIN_B"} {
		fs, err := Open(im, region)
		if err != nil {
			continue
		}
		free, err := fs.Free()
		if err != nil || free < 4096 {
			continue
		}
		if err := fs.AddRaw("cbprov/test", blob, CompressNone); err != nil {
			t.Fatalf("%s: %v", region, err)
		}
		runCbfstool(t, ref, "add", "-r", region, "-f", blobPath, "-n", "cbprov/test", "-t", "raw")
		if !bytes.Equal(readFile(t, ref), im.Data) {
			t.Fatalf("%s: add differs from cbfstool", region)
		}
		if err := fs.Remove("cbprov/test"); err != nil {
			t.Fatal(err)
		}
		runCbfstool(t, ref, "remove", "-r", region, "-n", "cbprov/test")
		if !bytes.Equal(readFile(t, ref), im.Data) {
			t.Fatalf("%s: remove differs from cbfstool", region)
		}
	}
}

func fixturePayloadSwap(t *testing.T, romPath string, data []byte, dir string) {
	im := parseImage(t, bytes.Clone(data))
	fs, err := Open(im, "COREBOOT")
	if err != nil {
		t.Fatal(err)
	}
	arch, ok := cbfsArch[fs.arch()]
	if !ok {
		arch = "x86" // real images leave the master header architecture unset
	}
	files, _ := fs.Files()
	var payload *File
	for i := range files {
		if files[i].Name == "fallback/payload" && files[i].Type == TypeSELF {
			payload = &files[i]
		}
	}
	if payload == nil {
		t.Logf("no SELF fallback/payload, skipping payload swap")
		return
	}
	// Prefer the fixture's own payload ELF, else round-trip the image's payload.
	elfPath := filepath.Join(filepath.Dir(romPath), "payload.elf")
	if _, err := os.Stat(elfPath); err != nil {
		elfPath = filepath.Join(dir, "payload.elf")
		runCbfstool(t, romPath, "extract", "-m", arch, "-n", "fallback/payload", "-f", elfPath)
	}
	elfData := readFile(t, elfPath)
	ver, err := DetectVerification(im)
	if err != nil {
		t.Fatal(err)
	}
	for _, comp := range []Compression{CompressNone, CompressLZMA, CompressLZ4} {
		im := parseImage(t, bytes.Clone(data))
		fs, _ := Open(im, "COREBOOT")
		if err := fs.Remove("fallback/payload"); err != nil {
			t.Fatal(err)
		}
		if err := fs.AddPayloadELF("fallback/payload", elfData, comp); err != nil {
			t.Fatal(err)
		}
		if err := UpdateMetadataHash(im); err != nil {
			t.Fatal(err)
		}
		ref := writeTemp(t, dir, "ref.rom", data)
		runCbfstool(t, ref, "remove", "-n", "fallback/payload")
		runCbfstool(t, ref, "add-payload", "-f", elfPath, "-n", "fallback/payload", "-c", compArg[comp])
		ours := writeTemp(t, dir, "ours.rom", im.Data)
		if comp == CompressNone && !bytes.Equal(readFile(t, ref), im.Data) {
			t.Errorf("uncompressed payload swap differs from cbfstool")
		}
		p := cbfstoolPrint(t, ours, "COREBOOT")
		if !p.hashesOK {
			t.Errorf("%v: invalid file hashes after swap", comp)
		}
		if ver.MetadataHash && (p.verifyLine != "fully valid" || !strings.HasSuffix(p.mdHash, ":valid")) {
			t.Errorf("%v: cbfstool verification %q %q", comp, p.verifyLine, p.mdHash)
		}
		a, b := filepath.Join(dir, "a.elf"), filepath.Join(dir, "b.elf")
		runCbfstool(t, ours, "extract", "-m", arch, "-n", "fallback/payload", "-f", a)
		runCbfstool(t, ref, "extract", "-m", arch, "-n", "fallback/payload", "-f", b)
		if !sameLoad(t, readFile(t, a), readFile(t, b)) {
			t.Errorf("%v: payload ELF export differs from cbfstool's", comp)
		}
		ourSize, refSize := payloadSize(t, ours), payloadSize(t, ref)
		t.Logf("%v: payload %d bytes (cbfstool %d, %+.1f%%)", comp, ourSize, refSize,
			100*(float64(ourSize)-float64(refSize))/float64(refSize))
	}
}

// sameLoad compares entry point and loadable segments of two ELFs; cbfstool's
// ELF export leaves uninitialized heap memory in its string table.
func sameLoad(t *testing.T, a, b []byte) bool {
	t.Helper()
	// Program headers parsed by hand: debug/elf rejects the garbage sections.
	load := func(raw []byte) string {
		if len(raw) < 52 || string(raw[:4]) != elf.ELFMAG || raw[elf.EI_DATA] != byte(elf.ELFDATA2LSB) {
			t.Fatal("not a little-endian ELF")
		}
		le := binary.LittleEndian
		is64 := raw[elf.EI_CLASS] == byte(elf.ELFCLASS64)
		var entry, phoff uint64
		var phentsize, phnum uint16
		if is64 {
			entry, phoff, phentsize, phnum = le.Uint64(raw[24:]), le.Uint64(raw[32:]), le.Uint16(raw[54:]), le.Uint16(raw[56:])
		} else {
			entry, phoff = uint64(le.Uint32(raw[24:])), uint64(le.Uint32(raw[28:]))
			phentsize, phnum = le.Uint16(raw[42:]), le.Uint16(raw[44:])
		}
		var s strings.Builder
		fmt.Fprintf(&s, "entry %#x\n", entry)
		for i := uint64(0); i < uint64(phnum); i++ {
			ph := raw[phoff+i*uint64(phentsize):]
			var typ, flags uint32
			var off, paddr, filesz, memsz uint64
			if is64 {
				typ, flags, off, paddr = le.Uint32(ph), le.Uint32(ph[4:]), le.Uint64(ph[8:]), le.Uint64(ph[24:])
				filesz, memsz = le.Uint64(ph[32:]), le.Uint64(ph[40:])
			} else {
				typ, off, paddr = le.Uint32(ph), uint64(le.Uint32(ph[4:])), uint64(le.Uint32(ph[12:]))
				filesz, memsz, flags = uint64(le.Uint32(ph[16:])), uint64(le.Uint32(ph[20:])), le.Uint32(ph[24:])
			}
			if elf.ProgType(typ) != elf.PT_LOAD {
				continue
			}
			fmt.Fprintf(&s, "%#x %#x %#x %#x %x\n", paddr, memsz, filesz, flags, sha256.Sum256(raw[off:off+filesz]))
		}
		return s.String()
	}
	return load(a) == load(b)
}

func payloadSize(t *testing.T, rom string) uint32 {
	for _, f := range cbfstoolPrint(t, rom, "COREBOOT").files {
		if f.Name == "fallback/payload" {
			return f.Size
		}
	}
	return 0
}
