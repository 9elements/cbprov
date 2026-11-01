// Command payload writes a minimal ELF payload that prints a message to the
// UART and halts.
//
//	go run ./test/payload -arch x86|arm64 -msg TEXT -o out.elf
package main

import (
	"flag"
	"log"
	"os"

	"github.com/9elements/cbprov/test/payload/elfgen"
)

func main() {
	arch := flag.String("arch", "x86", "x86 or arm64")
	msg := flag.String("msg", "CBPROV-PAYLOAD-A", "text to print")
	out := flag.String("o", "", "output ELF file")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	b, err := elfgen.Build(*arch, *msg)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}
