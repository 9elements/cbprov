package cbfs

import (
	"bytes"
	"fmt"
	"strings"
)

type span struct{ start, end uint64 }

// emptySpans returns the ranges cbfs_merge_empty_entry() would turn into
// single empty files: runs of empty files up to the next non-empty file or
// the end of the chain, clamped to the region size.
func emptySpans(es []entry, size int) []span {
	var ss []span
	for i := 0; i < len(es); i++ {
		if !es[i].empty() {
			continue
		}
		j := i
		for j+1 < len(es) && es[j+1].empty() {
			j++
		}
		ss = append(ss, span{uint64(es[i].off), min(es[j].next(), uint64(size))})
		i = j
	}
	return ss
}

func writeEmpty(buf []byte, off uint32, length uint32) {
	h := buf[off : off+emptyHeaderLen]
	copy(h, fileMagic)
	be.PutUint32(h[8:], length)
	be.PutUint32(h[12:], TypeNull)
	be.PutUint32(h[16:], 0)
	be.PutUint32(h[20:], emptyHeaderLen)
	clear(h[fileHeaderSize:])
	fill := buf[off+emptyHeaderLen : off+emptyHeaderLen+length]
	for i := range fill {
		fill[i] = contentDefault
	}
}

// mergeEmpty rewrites every run of empty (null or deleted) files as one null
// file, like cbfstool's cbfs_merge_empty_entry() walk.
func mergeEmpty(buf []byte) ([]entry, error) {
	es, err := walk(buf)
	if err != nil {
		return nil, err
	}
	for _, s := range emptySpans(es, len(buf)) {
		writeEmpty(buf, uint32(s.start), uint32(s.end-s.start-emptyHeaderLen))
	}
	return walk(buf)
}

func compressionAttr(comp Compression, decompSize uint32) []byte {
	a := make([]byte, 16)
	be.PutUint32(a, attrTagCompression)
	be.PutUint32(a[4:], 16)
	be.PutUint32(a[8:], uint32(comp))
	be.PutUint32(a[12:], decompSize)
	return a
}

func hashAttr(algo hashAlgo, data []byte) []byte {
	a := make([]byte, 12, 12+algo.size())
	be.PutUint32(a, attrTagHash)
	be.PutUint32(a[4:], uint32(12+algo.size()))
	a[11] = byte(algo)
	return append(a, algo.sum(data)...)
}

// fileHeader builds the metadata of a new file as cbfs_create_file_header()
// and cbfs_add_file_attr() do.
func fileHeader(name string, typ uint32, length uint32, attrs [][]byte) ([]byte, error) {
	nameLen := alignUp(uint32(len(name))+1, attrAlign)
	h := make([]byte, fileHeaderSize+nameLen)
	copy(h, fileMagic)
	be.PutUint32(h[8:], length)
	be.PutUint32(h[12:], typ)
	copy(h[fileHeaderSize:], name)
	if len(attrs) > 0 {
		be.PutUint32(h[16:], uint32(len(h)))
	}
	for _, a := range attrs {
		h = append(h, a...)
	}
	be.PutUint32(h[20:], uint32(len(h)))
	if len(h) > metadataMax {
		return nil, fmt.Errorf("cbfs: metadata of %q exceeds %d bytes", name, metadataMax)
	}
	return h, nil
}

// hashAlgo returns the hash algorithm new files need: the metadata anchor's
// (as cbfstool picks it) or else the one existing files in this CBFS carry.
func (fs *FS) hashAlgo(buf []byte, es []entry) (hashAlgo, error) {
	for _, c := range anchorContainers {
		if c.secondary != (fs.region == "COREBOOT_B") {
			continue
		}
		a, err := findAnchor(fs.im, c)
		if err != nil {
			return 0, err
		}
		if a != nil {
			return a.algo, nil
		}
	}
	for i := range es {
		if algo, _ := es[i].fileHash(buf); algo != 0 {
			return algo, nil
		}
	}
	return 0, nil
}

// add places a file into the first empty space that fits, like
// cbfs_add_entry() without a fixed offset.
func (fs *FS) add(name string, typ uint32, data []byte, attrs [][]byte) error {
	if err := validName(name); err != nil {
		return err
	}
	orig, es, err := fs.load()
	if err != nil {
		return err
	}
	for i := range es {
		if strings.EqualFold(es[i].name, name) && !es[i].empty() {
			return fmt.Errorf("cbfs: %q already exists in %s", name, fs.region)
		}
	}
	algo, err := fs.hashAlgo(orig, es)
	if err != nil {
		return err
	}
	if algo != 0 {
		attrs = append(attrs, hashAttr(algo, data))
	}
	hdr, err := fileHeader(name, typ, uint32(len(data)), attrs)
	if err != nil {
		return err
	}

	buf := bytes.Clone(orig)
	if es, err = mergeEmpty(buf); err != nil {
		return err
	}
	need := uint64(len(hdr)) + uint64(len(data))
	var largest uint64
	for _, e := range es {
		if e.typ != TypeNull {
			continue
		}
		addr, addrNext := uint64(e.off), min(e.next(), uint64(len(buf)))
		largest = max(largest, addrNext-addr)
		if addr+need > addrNext {
			continue
		}
		copy(buf[addr:], hdr)
		copy(buf[addr+uint64(len(hdr)):], data)
		next := (addr + need + alignment - 1) &^ (alignment - 1)
		if addrNext-next >= emptyHeaderLen {
			length := addrNext - next - emptyHeaderLen
			// cbfstool keeps the last 4 bytes free for the master header pointer.
			if next+emptyHeaderLen+length > uint64(len(buf))-4 && length >= 4 {
				length -= 4
			}
			writeEmpty(buf, uint32(next), uint32(length))
		}
		copy(orig, buf)
		return fs.afterChange()
	}
	return fmt.Errorf("cbfs: no space for %q in %s: need %d bytes (header %d + data %d), largest empty slot %d",
		name, fs.region, need, len(hdr), len(data), largest)
}
