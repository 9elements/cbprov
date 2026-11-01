package vpd

import (
	"bytes"
	"encoding/binary"
)

// Test oracle: a Go port of how coreboot locates and searches VPD
// (vpd.c init_vpd_rdev/vpd_find_in/vpd_gets, vpd_decode.c), kept close to
// the C control flow and its u32 arithmetic.

const (
	decodeOK   = 0
	decodeFail = 1
)

// cbInitRdev returns the data window coreboot decodes, or nil ("uninitialized").
func cbInitRdev(region []byte) []byte {
	size := int32(len(region))
	for _, offset := range []int{0, 0x600} {
		if int(size) < offset+16 {
			return nil
		}
		info := region[offset : offset+16]
		if bytes.Equal(info[:12], []byte("\xfe\x09\x01gVpdInfo\x04")) {
			infoSize := binary.LittleEndian.Uint32(info[12:])
			if uint64(offset+16)+uint64(infoSize) > uint64(len(region)) {
				return nil // "info size too large"
			}
			return region[offset+16 : offset+16+int(infoSize)]
		}
	}
	return nil
}

func cbDecodeLen(maxLen uint32, in []byte, length, decodedLen *uint32) int {
	var i uint32
	*length = 0
	for {
		if i >= maxLen {
			return decodeFail
		}
		more := in[i] & 0x80
		*length <<= 7
		*length |= uint32(in[i] & 0x7f)
		i++
		if more == 0 {
			break
		}
	}
	*decodedLen = i
	return decodeOK
}

func cbDecodeEntry(maxLen uint32, buf []byte, consumed *uint32, entry *[]byte, entryLen *uint32) int {
	var decodedLen uint32
	if cbDecodeLen(maxLen-*consumed, buf[*consumed:], entryLen, &decodedLen) != decodeOK {
		return decodeFail
	}
	if maxLen-*consumed < decodedLen {
		return decodeFail
	}
	*consumed += decodedLen
	if maxLen-*consumed < *entryLen {
		return decodeFail
	}
	*entry = buf[*consumed : *consumed+*entryLen]
	*consumed += *entryLen
	return decodeOK
}

func cbDecodeString(maxLen uint32, buf []byte, consumed *uint32, cb func(k, v []byte) int) int {
	if *consumed >= maxLen {
		return decodeFail
	}
	typ := buf[*consumed]
	switch typ {
	case 0xfe, 0x01:
		*consumed++
		var key, value []byte
		var kl, vl uint32
		if cbDecodeEntry(maxLen, buf, consumed, &key, &kl) != decodeOK {
			return decodeFail
		}
		if cbDecodeEntry(maxLen, buf, consumed, &value, &vl) != decodeOK {
			return decodeFail
		}
		if typ == 0x01 {
			return cb(key, value)
		}
		return decodeOK
	default:
		return decodeFail
	}
}

// cbWalk feeds every string entry coreboot sees to cb until cb returns decodeFail.
func cbWalk(region []byte, cb func(k, v []byte) int) {
	data := cbInitRdev(region)
	if len(data) == 0 {
		return
	}
	var consumed uint32
	for cbDecodeString(uint32(len(data)), data, &consumed, cb) == decodeOK {
	}
}

// cbFind is vpd_find on a single region.
func cbFind(region []byte, key string) ([]byte, bool) {
	var val []byte
	found := false
	cbWalk(region, func(k, v []byte) int {
		if string(k) != key {
			return decodeOK
		}
		val, found = v, true
		return decodeFail
	})
	return val, found
}

// cbGets is vpd_gets: at most size-1 bytes, cut at NUL like the C string.
func cbGets(region []byte, key string, size int) (string, bool) {
	v, ok := cbFind(region, key)
	if !ok {
		return "", false
	}
	v = v[:min(len(v), size-1)]
	if i := bytes.IndexByte(v, 0); i >= 0 {
		v = v[:i]
	}
	return string(v), true
}

// cbEntries lists all string entries in order.
func cbEntries(region []byte) []Entry {
	var out []Entry
	cbWalk(region, func(k, v []byte) int {
		out = append(out, Entry{Key: string(k), Value: bytes.Clone(v)})
		return decodeOK
	})
	return out
}
