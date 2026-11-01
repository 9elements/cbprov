package cbfs

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// LZ4 frame format as accepted by coreboot's ulz4fn(): version 1,
// independent blocks; cbfstool writes 4 MiB blocks without checksums.

const (
	lz4Magic        = 0x184D2204
	lz4BlockMax     = 4 << 20
	lz4MinMatch     = 4
	lz4LastLiterals = 5
	lz4MFLimit      = 12
	lz4MaxDist      = 65535
)

var errLZ4Corrupt = errors.New("lz4: corrupt stream")

func xxh32(b []byte, seed uint32) uint32 {
	const p1, p2, p3, p4, p5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
	n := len(b)
	var h uint32
	if n >= 16 {
		v1, v2, v3, v4 := seed+p1+p2, seed+p2, seed, seed-p1
		round := func(v, in uint32) uint32 { return bits.RotateLeft32(v+in*p2, 13) * p1 }
		for len(b) >= 16 {
			v1 = round(v1, binary.LittleEndian.Uint32(b))
			v2 = round(v2, binary.LittleEndian.Uint32(b[4:]))
			v3 = round(v3, binary.LittleEndian.Uint32(b[8:]))
			v4 = round(v4, binary.LittleEndian.Uint32(b[12:]))
			b = b[16:]
		}
		h = bits.RotateLeft32(v1, 1) + bits.RotateLeft32(v2, 7) + bits.RotateLeft32(v3, 12) + bits.RotateLeft32(v4, 18)
	} else {
		h = seed + p5
	}
	h += uint32(n)
	for ; len(b) >= 4; b = b[4:] {
		h = bits.RotateLeft32(h+binary.LittleEndian.Uint32(b)*p3, 17) * p4
	}
	for _, c := range b {
		h = bits.RotateLeft32(h+uint32(c)*p5, 11) * p1
	}
	h ^= h >> 15
	h *= p2
	h ^= h >> 13
	h *= p3
	h ^= h >> 16
	return h
}

func lz4Compress(data []byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, lz4Magic)
	desc := []byte{0x60, 0x70} // version 1, independent blocks; 4 MiB max block
	out = append(out, desc...)
	out = append(out, byte(xxh32(desc, 0)>>8))
	for len(data) > 0 {
		blk := data[:min(len(data), lz4BlockMax)]
		data = data[len(blk):]
		c := lz4CompressBlock(blk)
		if len(c) >= len(blk) {
			out = binary.LittleEndian.AppendUint32(out, uint32(len(blk))|0x80000000)
			out = append(out, blk...)
		} else {
			out = binary.LittleEndian.AppendUint32(out, uint32(len(c)))
			out = append(out, c...)
		}
	}
	return binary.LittleEndian.AppendUint32(out, 0)
}

func lz4AppendLen(out []byte, n int) []byte {
	for ; n >= 255; n -= 255 {
		out = append(out, 255)
	}
	return append(out, byte(n))
}

func lz4Sequence(out, lits []byte, off, mlen int) []byte {
	tok := byte(min(len(lits), 15)) << 4
	if mlen > 0 {
		tok |= byte(min(mlen-lz4MinMatch, 15))
	}
	out = append(out, tok)
	if len(lits) >= 15 {
		out = lz4AppendLen(out, len(lits)-15)
	}
	out = append(out, lits...)
	if mlen == 0 {
		return out
	}
	out = binary.LittleEndian.AppendUint16(out, uint16(off))
	if mlen-lz4MinMatch >= 15 {
		out = lz4AppendLen(out, mlen-lz4MinMatch-15)
	}
	return out
}

func lz4CompressBlock(src []byte) []byte {
	n := len(src)
	out := make([]byte, 0, n/2+16)
	anchor := 0
	if n > lz4MFLimit {
		mf := newMatchFinder(src, 64, 256, 1<<30, lz4MinMatch, lz4MaxDist)
		matchEnd := n - lz4LastLiterals
		for i := 0; i < n-lz4MFLimit; {
			l, d := mf.find(i, matchEnd, lz4MaxDist)
			if l < lz4MinMatch {
				i++
				continue
			}
			if i+1 < n-lz4MFLimit {
				if nl, _ := mf.find(i+1, matchEnd, lz4MaxDist); nl > l {
					i++
					continue
				}
			}
			out = lz4Sequence(out, src[anchor:i], d, l)
			i += l
			anchor = i
		}
	}
	return lz4Sequence(out, src[anchor:], 0, 0)
}

// lz4Decompress decodes an LZ4 frame, producing at most limit bytes.
func lz4Decompress(src []byte, limit uint64) ([]byte, error) {
	if len(src) < 7 || binary.LittleEndian.Uint32(src) != lz4Magic {
		return nil, errors.New("lz4: bad frame header")
	}
	flg := src[4]
	if flg>>6 != 1 {
		return nil, errors.New("lz4: unsupported frame version")
	}
	p := 6
	if flg&0x08 != 0 {
		p += 8
	}
	if flg&0x01 != 0 {
		p += 4
	}
	p++ // header checksum
	out := make([]byte, 0, min(limit, 64<<20))
	for {
		if p+4 > len(src) {
			return nil, errLZ4Corrupt
		}
		v := binary.LittleEndian.Uint32(src[p:])
		p += 4
		if v == 0 {
			break
		}
		sz := int(v & 0x7FFFFFFF)
		if p+sz > len(src) {
			return nil, errLZ4Corrupt
		}
		blk := src[p : p+sz]
		p += sz
		if flg&0x10 != 0 {
			p += 4
		}
		var err error
		if v&0x80000000 != 0 {
			out = append(out, blk...)
		} else if out, err = lz4DecodeBlock(out, blk, limit); err != nil {
			return nil, err
		}
		if uint64(len(out)) > limit {
			return nil, errors.New("lz4: output exceeds expected size")
		}
	}
	return out, nil
}

func lz4DecodeBlock(out, in []byte, limit uint64) ([]byte, error) {
	readLen := func(p int, n int) (int, int, error) {
		if n != 15 {
			return n, p, nil
		}
		for {
			if p >= len(in) {
				return 0, 0, errLZ4Corrupt
			}
			b := in[p]
			p++
			n += int(b)
			if b != 255 {
				return n, p, nil
			}
		}
	}
	p := 0
	for p < len(in) {
		tok := in[p]
		p++
		lit, np, err := readLen(p, int(tok>>4))
		if err != nil {
			return nil, err
		}
		p = np
		if p+lit > len(in) {
			return nil, errLZ4Corrupt
		}
		out = append(out, in[p:p+lit]...)
		p += lit
		if p == len(in) {
			return out, nil
		}
		if p+2 > len(in) {
			return nil, errLZ4Corrupt
		}
		off := int(binary.LittleEndian.Uint16(in[p:]))
		p += 2
		ml, np, err := readLen(p, int(tok&15))
		if err != nil {
			return nil, err
		}
		p = np
		ml += lz4MinMatch
		if off == 0 || off > len(out) || uint64(len(out)+ml) > limit {
			return nil, errLZ4Corrupt
		}
		from := len(out) - off
		for i := 0; i < ml; i++ {
			out = append(out, out[from+i])
		}
	}
	return nil, errLZ4Corrupt
}
