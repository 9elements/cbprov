// Package elfgen builds minimal ELF payloads that print a message to the
// UART and halt. They are used as coreboot test payloads.
package elfgen

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Load and entry addresses of the generated payloads.
const (
	X86Base   = 0x01000000
	ARM64Base = 0x40200000 // qemu virt DRAM starts at 0x40000000; the first MiB holds the FDT
	PL011Base = 0x09000000
)

// Build returns an ELF payload for arch ("x86" or "arm64") printing msg plus CRLF.
func Build(arch, msg string) ([]byte, error) {
	if bytes.IndexByte([]byte(msg), 0) >= 0 {
		return nil, fmt.Errorf("message must not contain NUL")
	}
	text := append([]byte(msg+"\r\n"), 0)
	switch arch {
	case "x86":
		return elf32(x86Code(text)), nil
	case "arm64":
		return elf64(arm64Code(text)), nil
	}
	return nil, fmt.Errorf("unsupported arch %q (x86, arm64)", arch)
}

// x86Code uses only instructions that decode identically in 32- and 64-bit
// mode, since coreboot may hand over in either.
func x86Code(text []byte) []byte {
	code := []byte{
		0xfa,             // cli
		0xfc,             // cld
		0xbe, 0, 0, 0, 0, // mov esi, imm32 (patched below)
		0x66, 0xba, 0xf8, 0x03, // mov dx, 0x3f8
		// next:
		0xac,       // lodsb
		0x84, 0xc0, // test al, al
		0x74, 0x10, // jz halt
		0x88, 0xc4, // mov ah, al
		0xb2, 0xfd, // mov dl, 0xfd (LSR)
		// poll:
		0xec,       // in al, dx
		0xa8, 0x20, // test al, 0x20 (THRE)
		0x74, 0xfb, // jz poll
		0xb2, 0xf8, // mov dl, 0xf8 (THR)
		0x88, 0xe0, // mov al, ah
		0xee,       // out dx, al
		0xeb, 0xeb, // jmp next
		// halt:
		0xf4,       // hlt
		0xeb, 0xfd, // jmp halt
	}
	binary.LittleEndian.PutUint32(code[3:], uint32(X86Base+len(code)))
	return append(code, text...)
}

func arm64Code(text []byte) []byte {
	const (
		x1 = 1
		x2 = 2
		w3 = 3
		w4 = 4
	)
	var ins []uint32
	emit := func(i uint32) int { ins = append(ins, i); return len(ins) - 1 }
	rel := func(from, to int) uint32 { return uint32(int32(to - from)) }

	emit(0xd2a00000 | (PL011Base>>16)<<5 | x1)              // movz x1, #0x0900, lsl #16
	adr := emit(0)                                          // adr x2, text
	loop := emit(0x38401400 | x2<<5 | w3)                   // ldrb w3, [x2], #1
	cbz := emit(0)                                          // cbz w3, halt
	poll := emit(0xb9401800 | x1<<5 | w4)                   // ldr w4, [x1, #0x18] (UARTFR)
	emit(0x37280000 | (rel(len(ins), poll)&0x3fff)<<5 | w4) // tbnz w4, #5 (TXFF), poll
	emit(0xb9000000 | x1<<5 | w3)                           // str w3, [x1] (UARTDR)
	emit(0x14000000 | rel(len(ins), loop)&0x3ffffff)        // b loop
	halt := emit(0xd503207f)                                // wfi
	emit(0x14000000 | rel(len(ins), halt)&0x3ffffff)        // b halt

	ins[cbz] = 0x34000000 | (rel(cbz, halt)&0x7ffff)<<5 | w3
	off := uint32(len(ins)*4 - adr*4)
	ins[adr] = 0x10000000 | (off&3)<<29 | ((off>>2)&0x7ffff)<<5 | x2

	code := make([]byte, 0, len(ins)*4+len(text))
	for _, i := range ins {
		code = binary.LittleEndian.AppendUint32(code, i)
	}
	return append(code, text...)
}

const (
	ptLoad  = 1
	pfRWX   = 7
	codeOff = 0x100
)

func elf32(code []byte) []byte {
	b := make([]byte, codeOff, codeOff+len(code))
	copy(b, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2) // ET_EXEC
	le.PutUint16(b[18:], 3) // EM_386
	le.PutUint32(b[20:], 1) // EV_CURRENT
	le.PutUint32(b[24:], X86Base)
	le.PutUint32(b[28:], 52) // e_phoff
	le.PutUint16(b[40:], 52) // e_ehsize
	le.PutUint16(b[42:], 32) // e_phentsize
	le.PutUint16(b[44:], 1)  // e_phnum
	le.PutUint16(b[46:], 40) // e_shentsize
	p := b[52:]
	le.PutUint32(p[0:], ptLoad)
	le.PutUint32(p[4:], codeOff)
	le.PutUint32(p[8:], X86Base)
	le.PutUint32(p[12:], X86Base)
	le.PutUint32(p[16:], uint32(len(code)))
	le.PutUint32(p[20:], uint32(len(code)))
	le.PutUint32(p[24:], pfRWX)
	le.PutUint32(p[28:], 0x100)
	return append(b, code...)
}

func elf64(code []byte) []byte {
	b := make([]byte, codeOff, codeOff+len(code))
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2)   // ET_EXEC
	le.PutUint16(b[18:], 183) // EM_AARCH64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[24:], ARM64Base)
	le.PutUint64(b[32:], 64) // e_phoff
	le.PutUint16(b[52:], 64) // e_ehsize
	le.PutUint16(b[54:], 56) // e_phentsize
	le.PutUint16(b[56:], 1)
	le.PutUint16(b[58:], 64) // e_shentsize
	p := b[64:]
	le.PutUint32(p[0:], ptLoad)
	le.PutUint32(p[4:], pfRWX)
	le.PutUint64(p[8:], codeOff)
	le.PutUint64(p[16:], ARM64Base)
	le.PutUint64(p[24:], ARM64Base)
	le.PutUint64(p[32:], uint64(len(code)))
	le.PutUint64(p[40:], uint64(len(code)))
	le.PutUint64(p[48:], 0x100)
	return append(b, code...)
}
