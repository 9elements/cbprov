// Package vpd reads and writes Google VPD 2.0 key/value stores as used by
// coreboot's src/drivers/vpd (FMAP regions RO_VPD and RW_VPD).
//
// Region layout as coreboot reads it (vpd.c, vpd_decode.c, vpd_tables.h):
//
//	0x00  fe 09 01 "gVpdInfo" 04   google_vpd_info magic (itself an info-type entry)
//	0x0c  u32le size               bytes of entry data following the header
//	0x10  01 <len> key <len> value one string entry per key
//	      00                       terminator
//	      ff ...                   erased padding
//
// Lengths are big-endian base-128: 7 bits per byte, bit 7 set on all but the
// last byte. coreboot looks for the header at offset 0, then at the legacy
// offset 0x600; without it the region is treated as empty.
package vpd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Entry types (vpd_decode.h).
const (
	TypeTerminator         = 0x00
	TypeString             = 0x01
	TypeInfo               = 0xfe
	TypeImplicitTerminator = 0xff
)

// HeaderSize is the size of the google_vpd_info header.
const HeaderSize = 16

// LegacyOffset is GOOGLE_VPD_2_0_OFFSET, the fallback header location.
const LegacyOffset = 0x600

var infoMagic = []byte("\xfe\x09\x01gVpdInfo\x04")

// ErrNoHeader means the region is neither erased nor carries a google_vpd_info
// header. coreboot ignores such a region; overwriting it discards its content.
var ErrNoHeader = errors.New("vpd: no gVpdInfo header at 0x0 or 0x600 and region not erased")

// Entry is one key/value pair. Values are raw bytes; strings are not NUL terminated.
type Entry struct {
	Key   string
	Value []byte
}

// Store is a decoded VPD region. Entries keep their on-flash order.
type Store struct {
	Entries []Entry
	// Size is the size of the region the store was decoded from; Encode pads to it.
	Size int
}

// Decode parses a VPD region. An erased region (all 0xff) yields an empty store.
// It fails on anything coreboot would not read completely (unknown entry
// types, truncated entries), so a decode/encode cycle never drops data silently.
func Decode(region []byte) (*Store, error) {
	s := New(len(region))
	off := -1
	for _, o := range []int{0, LegacyOffset} {
		if len(region) >= o+HeaderSize && bytes.Equal(region[o:o+len(infoMagic)], infoMagic) {
			off = o
			break
		}
	}
	if off < 0 {
		if isErased(region) {
			return s, nil
		}
		return nil, ErrNoHeader
	}
	size := binary.LittleEndian.Uint32(region[off+12 : off+HeaderSize])
	base := off + HeaderSize
	data := region[base:]
	if uint64(size) > uint64(len(data)) {
		return nil, fmt.Errorf("vpd: header size %#x exceeds the %#x bytes after the header at %#x", size, len(data), off)
	}
	data = data[:size]

	for p := 0; p < len(data); {
		typ := data[p]
		switch typ {
		case TypeTerminator, TypeImplicitTerminator:
			return s, nil
		case TypeString, TypeInfo:
		default:
			return nil, fmt.Errorf("vpd: unknown entry type %#02x at offset %#x", typ, base+p)
		}
		start := base + p
		key, n, err := field(data, p+1)
		if err != nil {
			return nil, fmt.Errorf("vpd: entry at offset %#x: key: %w", start, err)
		}
		val, m, err := field(data, p+1+n)
		if err != nil {
			return nil, fmt.Errorf("vpd: entry at offset %#x: value: %w", start, err)
		}
		p += 1 + n + m
		if typ == TypeString {
			s.Entries = append(s.Entries, Entry{Key: string(key), Value: bytes.Clone(val)})
		}
	}
	// coreboot also stops cleanly at the end of the data without a terminator.
	return s, nil
}

// field decodes the length-prefixed byte string at data[p:] and returns it
// with the number of bytes consumed.
func field(data []byte, p int) ([]byte, int, error) {
	var l uint64
	i := p
	for {
		if i >= len(data) {
			return nil, 0, errors.New("truncated length")
		}
		b := data[i]
		i++
		l = l<<7 | uint64(b&0x7f)
		if l > uint64(len(data)) {
			return nil, 0, fmt.Errorf("length %#x exceeds data", l)
		}
		if b&0x80 == 0 {
			break
		}
	}
	if l > uint64(len(data)-i) {
		return nil, 0, fmt.Errorf("length %#x exceeds data", l)
	}
	end := i + int(l)
	return data[i:end], end - p, nil
}

func isErased(b []byte) bool {
	for _, c := range b {
		if c != 0xff {
			return false
		}
	}
	return true
}

// New returns an empty store for a region of the given size.
func New(size int) *Store { return &Store{Size: size} }

// Get returns the value of key. As in coreboot, the first match wins.
func (s *Store) Get(key string) ([]byte, bool) {
	for _, e := range s.Entries {
		if e.Key == key {
			return e.Value, true
		}
	}
	return nil, false
}

// Set adds or replaces key, keeping the position of an existing key.
// Shadowed duplicates of key are dropped.
func (s *Store) Set(key string, value []byte) error {
	if err := CheckKey(key); err != nil {
		return err
	}
	v := append([]byte{}, value...)
	found := false
	out := s.Entries[:0]
	for _, e := range s.Entries {
		if e.Key == key {
			if found {
				continue
			}
			found = true
			e.Value = v
		}
		out = append(out, e)
	}
	clear(s.Entries[len(out):])
	if !found {
		out = append(out, Entry{Key: key, Value: v})
	}
	s.Entries = out
	return nil
}

// Delete removes key; it reports whether the key existed.
func (s *Store) Delete(key string) bool {
	out := s.Entries[:0]
	for _, e := range s.Entries {
		if e.Key != key {
			out = append(out, e)
		}
	}
	found := len(out) != len(s.Entries)
	clear(s.Entries[len(out):])
	s.Entries = out
	return found
}

// CheckKey reports whether key is a valid VPD key name: non-empty and made of
// [A-Za-z0-9_.], the set the vpd utility and Linux' VPD sysfs driver accept.
func CheckKey(key string) error {
	if key == "" {
		return errors.New("vpd: empty key")
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return fmt.Errorf("vpd: key %q: invalid character %q (allowed: A-Z a-z 0-9 _ .)", key, c)
		}
	}
	return nil
}

// EncodedSize returns the number of bytes Encode needs, header included.
func (s *Store) EncodedSize() int {
	n := HeaderSize + 1 // terminator
	for _, e := range s.Entries {
		n += 1 + lenSize(len(e.Key)) + len(e.Key) + lenSize(len(e.Value)) + len(e.Value)
	}
	return n
}

// Encode serialises the store into a buffer of s.Size bytes, padded with 0xff.
// The header goes to offset 0. It fails if the entries do not fit.
func (s *Store) Encode() ([]byte, error) {
	for _, e := range s.Entries {
		if err := CheckKey(e.Key); err != nil {
			return nil, err
		}
	}
	need := s.EncodedSize()
	if need > s.Size {
		return nil, fmt.Errorf("vpd: entries need %d bytes, region has %d (%d bytes over)", need, s.Size, need-s.Size)
	}
	buf := make([]byte, 0, s.Size)
	buf = append(buf, infoMagic...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(need-HeaderSize))
	for _, e := range s.Entries {
		buf = append(buf, TypeString)
		buf = appendLen(buf, len(e.Key))
		buf = append(buf, e.Key...)
		buf = appendLen(buf, len(e.Value))
		buf = append(buf, e.Value...)
	}
	buf = append(buf, TypeTerminator)
	for len(buf) < s.Size {
		buf = append(buf, 0xff)
	}
	return buf, nil
}

func lenSize(n int) int {
	i := 1
	for n >>= 7; n > 0; n >>= 7 {
		i++
	}
	return i
}

func appendLen(buf []byte, n int) []byte {
	for i := lenSize(n) - 1; i > 0; i-- {
		buf = append(buf, byte(n>>(7*i))&0x7f|0x80)
	}
	return append(buf, byte(n)&0x7f)
}
