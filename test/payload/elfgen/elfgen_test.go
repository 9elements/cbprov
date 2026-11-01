package elfgen

import (
	"bytes"
	"debug/elf"
	"testing"
)

func TestBuild(t *testing.T) {
	for _, tc := range []struct {
		arch    string
		class   elf.Class
		machine elf.Machine
		base    uint64
	}{
		{"x86", elf.ELFCLASS32, elf.EM_386, X86Base},
		{"arm64", elf.ELFCLASS64, elf.EM_AARCH64, ARM64Base},
	} {
		t.Run(tc.arch, func(t *testing.T) {
			b, err := Build(tc.arch, "CBPROV-PAYLOAD-A")
			if err != nil {
				t.Fatal(err)
			}
			f, err := elf.NewFile(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			if f.Class != tc.class || f.Machine != tc.machine || f.Type != elf.ET_EXEC {
				t.Fatalf("got %v %v %v", f.Class, f.Machine, f.Type)
			}
			if f.Entry != tc.base {
				t.Fatalf("entry %#x, want %#x", f.Entry, tc.base)
			}
			if len(f.Progs) != 1 {
				t.Fatalf("%d program headers", len(f.Progs))
			}
			p := f.Progs[0]
			if p.Type != elf.PT_LOAD || p.Vaddr != tc.base || p.Paddr != tc.base || p.Flags&elf.PF_X == 0 {
				t.Fatalf("bad segment %+v", p.ProgHeader)
			}
			data := make([]byte, p.Filesz)
			if _, err := p.ReadAt(data, 0); err != nil {
				t.Fatal(err)
			}
			if !bytes.HasSuffix(data, []byte("CBPROV-PAYLOAD-A\r\n\x00")) {
				t.Fatalf("message missing in segment")
			}
		})
	}
}

func TestX86MessagePointer(t *testing.T) {
	b, _ := Build("x86", "hi")
	f, _ := elf.NewFile(bytes.NewReader(b))
	data := make([]byte, f.Progs[0].Filesz)
	f.Progs[0].ReadAt(data, 0)
	ptr := uint32(data[3]) | uint32(data[4])<<8 | uint32(data[5])<<16 | uint32(data[6])<<24
	if got := string(data[ptr-X86Base:]); got != "hi\r\n\x00" {
		t.Fatalf("mov esi points at %q", got)
	}
}

func TestBadInput(t *testing.T) {
	if _, err := Build("riscv", "x"); err == nil {
		t.Error("unknown arch accepted")
	}
	if _, err := Build("x86", "a\x00b"); err == nil {
		t.Error("NUL accepted")
	}
}
