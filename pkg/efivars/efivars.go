// Package efivars reads and writes an EDK2 variable store inside a firmware
// volume, the format coreboot uses in the SMMSTORE region
// (src/drivers/efi/efivars.c).
//
// Parsing is as strict as coreboot's reader: a store coreboot would reject
// (bad headers, unknown record states, non-erased bytes after the last
// record) fails with ErrCorrupt. Writes only touch the variable area
// [HeaderLength+28, HeaderLength+Size); the FTW working and spare areas behind
// it are kept byte-identical.
package efivars

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

var (
	// ErrCorrupt means the region holds no store coreboot would accept.
	ErrCorrupt = errors.New("efivars: corrupt variable store")
	// ErrStoreFull means the variable does not fit even after reclaim.
	ErrStoreFull = errors.New("efivars: variable store full")
	// ErrInvalid reports an invalid argument.
	ErrInvalid = errors.New("efivars: invalid argument")
)

// GUID is an EFI GUID in its on-flash (mixed-endian) byte layout.
type GUID [16]byte

// CorebootNvDataGUID is the vendor GUID of coreboot option variables
// (ceae4c1d-335b-4685-a4a0-fc4a94eea085, src/drivers/efi/option.c).
var CorebootNvDataGUID = MustParseGUID("ceae4c1d-335b-4685-a4a0-fc4a94eea085")

// Default attributes coreboot writes for option variables
// (efi_fv_set_option: NV|BS|RT).
const (
	AttrNonVolatile       = 0x1
	AttrBootserviceAccess = 0x2
	AttrRuntimeAccess     = 0x4
	DefaultAttributes     = AttrNonVolatile | AttrBootserviceAccess | AttrRuntimeAccess
)

// Variable is one valid (non-deleted) variable.
type Variable struct {
	GUID       GUID
	Name       string
	Attributes uint32
	Data       []byte
}

// record is one variable record in the store, in any state.
type record struct {
	off     int // absolute offset in region
	size    int // header+name+data, unaligned
	hdr     header
	rawName []byte // UTF-16LE including terminator
}

func (r *record) live() bool {
	return r.hdr.state == stateAdded || r.hdr.state == stateTransition
}

type varKey struct {
	guid GUID
	name string // raw UTF-16LE bytes
}

func (r *record) key() varKey { return varKey{r.hdr.guid, string(r.rawName)} }

// Store is a parsed variable store. Bytes() returns the full region, so data
// outside the store (e.g. FTW areas) is kept unchanged.
type Store struct {
	region     []byte
	auth       bool
	start, end int // variable area
	free       int // first byte after the last record
	recs       []record
}

// Parse parses a region that starts with an EDK2 firmware volume header. The
// region is copied; the Store never modifies the caller's slice.
func Parse(region []byte) (*Store, error) {
	s := &Store{region: bytes.Clone(region)}
	if err := s.parseHeaders(); err != nil {
		return nil, err
	}
	if err := s.walk(); err != nil {
		return nil, err
	}
	return s, nil
}

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, a...))
}

// parseHeaders applies coreboot's validate_fv_header and
// validate_variable_store_header checks.
func (s *Store) parseHeaders() error {
	r := s.region
	if len(r) < fvHeaderLen {
		return corrupt("region too small (%d bytes)", len(r))
	}
	fvLen := le.Uint64(r[32:])
	hl := int(le.Uint16(r[48:]))
	if r[55] != fvRevision || le.Uint32(r[40:]) != fvSignature {
		return corrupt("no firmware volume header")
	}
	if fvLen > uint64(len(r)) || hl < fvHeaderLen || uint64(hl) > fvLen ||
		fvLen-uint64(hl) < storeHeaderLen || hl&1 != 0 {
		return corrupt("firmware volume length %#x / header length %#x invalid", fvLen, hl)
	}
	if GUID(r[16:32]) != systemNvDataFvGUID {
		return corrupt("firmware volume GUID %s is not EFI_SYSTEM_NV_DATA_FV", GUID(r[16:32]))
	}
	if c := checksum16(r[:hl]); c != 0 {
		return corrupt("firmware volume header checksum %#04x", c)
	}
	var mapped uint64
	terminated := false
	for off := fvBlockMapOff; off+8 <= hl; off += 8 {
		n, l := uint64(le.Uint32(r[off:])), uint64(le.Uint32(r[off+4:]))
		if n == 0 && l == 0 {
			terminated = true
			break
		}
		if n == 0 || l == 0 || n > (math.MaxUint64-mapped)/l {
			return corrupt("firmware volume block map entry invalid")
		}
		mapped += n * l
	}
	if !terminated || mapped != fvLen {
		return corrupt("firmware volume block map does not cover %#x bytes", fvLen)
	}

	sh := r[hl : hl+storeHeaderLen]
	switch GUID(sh[:16]) {
	case authVariableGUID:
		s.auth = true
	case variableGUID:
	default:
		return corrupt("variable store GUID %s unknown", GUID(sh[:16]))
	}
	size := uint64(le.Uint32(sh[16:]))
	if size <= storeHeaderLen || size > fvLen-uint64(hl) {
		return corrupt("variable store size %#x invalid", size)
	}
	if sh[20] != storeFormatted || sh[21] != storeHealthy {
		return corrupt("variable store not formatted/healthy (%#02x/%#02x)", sh[20], sh[21])
	}
	s.start, s.end = hl+storeHeaderLen, hl+int(size)
	// EDK2 aligns the first record to 4 bytes, coreboot does not; they only
	// agree when the start is already aligned.
	if s.start%headerAlign != 0 {
		return corrupt("variable area start %#x not %d-byte aligned", s.start, headerAlign)
	}
	return nil
}

func (s *Store) headerLen() int {
	if s.auth {
		return authHeaderLen
	}
	return plainHeaderLen
}

// walk rebuilds the record list like coreboot's walk_variables.
func (s *Store) walk() error {
	hl := s.headerLen()
	s.recs = s.recs[:0]
	off := s.start
	for off < s.end {
		rem := s.end - off
		if rem < hl || le.Uint16(s.region[off:]) != startID {
			if !IsErased(s.region[off:s.end]) {
				return corrupt("non-erased data after last variable at %#x", off)
			}
			break
		}
		h := readHeader(s.region[off:], s.auth)
		if !validState(h.state) {
			return corrupt("variable at %#x has invalid state %#02x", off, h.state)
		}
		size := uint64(hl) + uint64(h.nameSize) + uint64(h.dataSize)
		if size > uint64(rem) || alignUp(int(size)) > rem {
			return corrupt("variable at %#x overflows the store", off)
		}
		if h.nameSize < 2 || h.nameSize%2 != 0 {
			return corrupt("variable at %#x has name size %d", off, h.nameSize)
		}
		rawName := s.region[off+hl : off+hl+int(h.nameSize)]
		// Header-only records may lack name and data; coreboot skips them.
		if h.state != 0xff && h.state != stateHeaderValidOnly &&
			le.Uint16(rawName[len(rawName)-2:]) != 0 {
			return corrupt("variable at %#x has unterminated name", off)
		}
		s.recs = append(s.recs, record{off: off, size: int(size), hdr: h, rawName: bytes.Clone(rawName)})
		off += alignUp(int(size))
	}
	s.free = off
	return nil
}

// find returns the record coreboot and EDK2 read for a name: the first
// VAR_ADDED one, else the last one in deleted transition; -1 if none.
func (s *Store) find(guid GUID, rawName []byte) int {
	found := -1
	for i := range s.recs {
		r := &s.recs[i]
		if !r.live() || r.hdr.guid != guid || !bytes.Equal(r.rawName, rawName) {
			continue
		}
		if r.hdr.state == stateAdded {
			return i
		}
		found = i
	}
	return found
}

func (s *Store) data(r *record) []byte {
	o := r.off + s.headerLen() + int(r.hdr.nameSize)
	return s.region[o : o+int(r.hdr.dataSize)]
}

func (s *Store) variable(r *record) Variable {
	return Variable{
		GUID:       r.hdr.guid,
		Name:       decodeName(r.rawName),
		Attributes: r.hdr.attrs,
		Data:       bytes.Clone(s.data(r)),
	}
}

// Variables lists all valid variables in store order.
func (s *Store) Variables() []Variable {
	var out []Variable
	for i := range s.recs {
		r := &s.recs[i]
		if r.live() && s.find(r.hdr.guid, r.rawName) == i {
			out = append(out, s.variable(r))
		}
	}
	return out
}

// Get returns the valid variable with that GUID and name.
func (s *Store) Get(guid GUID, name string) (*Variable, bool) {
	rawName, err := encodeName(name)
	if err != nil {
		return nil, false
	}
	i := s.find(guid, rawName)
	if i < 0 {
		return nil, false
	}
	v := s.variable(&s.recs[i])
	return &v, true
}

func checkAttrs(attrs uint32) error {
	switch {
	case attrs&AttrNonVolatile == 0:
		return fmt.Errorf("%w: attributes %#x lack NON_VOLATILE", ErrInvalid, attrs)
	case attrs&AttrRuntimeAccess != 0 && attrs&AttrBootserviceAccess == 0:
		return fmt.Errorf("%w: attributes %#x: RUNTIME_ACCESS needs BOOTSERVICE_ACCESS", ErrInvalid, attrs)
	case attrs&(attrAuthWrite|attrAppendWrite) != 0:
		return fmt.Errorf("%w: attributes %#x: authenticated/append writes unsupported", ErrInvalid, attrs)
	case attrs&^(DefaultAttributes|attrHardwareErrorRecord) != 0:
		return fmt.Errorf("%w: unknown attributes %#x", ErrInvalid, attrs)
	}
	return nil
}

// Set writes a variable the way the firmware does: if an identical variable
// exists nothing changes; otherwise the new record is appended and the old one
// marked deleted. If the store is full it is reclaimed first. Authenticated
// variables (e.g. Secure Boot keys) cannot be overwritten, only deleted.
func (s *Store) Set(guid GUID, name string, attrs uint32, data []byte) error {
	rawName, err := encodeName(name)
	if err != nil {
		return err
	}
	if err := checkAttrs(attrs); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%w: empty data (use Delete)", ErrInvalid)
	}
	if uint64(len(data)) > math.MaxUint32 {
		return fmt.Errorf("%w: data too large", ErrStoreFull)
	}
	if i := s.find(guid, rawName); i >= 0 {
		r := &s.recs[i]
		if r.hdr.attrs&attrAuthWrite != 0 {
			return fmt.Errorf("%w: %s:%s is an authenticated variable", ErrInvalid, guid, name)
		}
		if r.hdr.attrs == attrs && bytes.Equal(s.data(r), data) {
			return nil
		}
	}

	rec := encodeRecord(s.auth, guid, rawName, attrs, data)
	if alignUp(len(rec)) > s.end-s.free {
		return s.reclaim(varKey{guid, string(rawName)}, rec)
	}
	s.markDeleted(guid, rawName)
	copy(s.region[s.free:], rec)
	return s.walk()
}

// Delete marks a variable deleted; it reports whether it existed.
func (s *Store) Delete(guid GUID, name string) (bool, error) {
	rawName, err := encodeName(name)
	if err != nil {
		return false, err
	}
	if s.find(guid, rawName) < 0 {
		return false, nil
	}
	s.markDeleted(guid, rawName)
	return true, s.walk()
}

// markDeleted moves every live record of the name to the final deleted state
// (EDK2 goes through IN_DELETED_TRANSITION; offline only the end state matters).
func (s *Store) markDeleted(guid GUID, rawName []byte) {
	for i := range s.recs {
		r := &s.recs[i]
		if r.live() && r.hdr.guid == guid && bytes.Equal(r.rawName, rawName) {
			s.region[r.off+2] &= stateDeletedFinal
		}
	}
}

// reclaim compacts the store like EDK2's Reclaim(): VAR_ADDED records in
// store order, then in-transition records without a VAR_ADDED copy (promoted
// to VAR_ADDED), then rec. Records named skip are dropped. On ErrStoreFull
// the store is left unchanged.
func (s *Store) reclaim(skip varKey, rec []byte) error {
	buf := bytes.Repeat([]byte{0xff}, s.end-s.start)
	pos := 0
	put := func(b []byte) bool {
		if alignUp(len(b)) > len(buf)-pos {
			return false
		}
		copy(buf[pos:], b)
		pos += alignUp(len(b))
		return true
	}
	kept := map[varKey]bool{}
	for i := range s.recs {
		r := &s.recs[i]
		if k := r.key(); r.hdr.state == stateAdded && k != skip && !kept[k] {
			kept[k] = true
			put(s.region[r.off : r.off+r.size]) // always fits: subset of the current area
		}
	}
	for i := range s.recs {
		r := &s.recs[i]
		k := r.key()
		if r.hdr.state != stateTransition || k == skip || kept[k] || s.find(r.hdr.guid, r.rawName) != i {
			continue
		}
		kept[k] = true
		b := bytes.Clone(s.region[r.off : r.off+r.size])
		b[2] = stateAdded
		put(b)
	}
	if !put(rec) {
		return fmt.Errorf("%w: %d bytes needed, %d free after reclaim", ErrStoreFull, alignUp(len(rec)), len(buf)-pos)
	}
	copy(s.region[s.start:s.end], buf)
	return s.walk()
}

// Format returns a freshly initialised store region of size bytes, as
// coreboot's efi_fv_initialize() would write it. blockSize is SMM_BLOCK_SIZE.
// The variable area gets n - n/2 - 1 of the n blocks (rest: FTW spare and
// working block); FvLength covers the whole region.
func Format(size, blockSize int) ([]byte, error) {
	if blockSize <= 0 || uint64(blockSize) > math.MaxUint32 || size <= 0 || size%blockSize != 0 {
		return nil, fmt.Errorf("%w: size %#x not a multiple of block size %#x", ErrInvalid, size, blockSize)
	}
	n := size / blockSize
	if n < 4 || uint64(n) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %d blocks, need at least 4", ErrInvalid, n)
	}
	vss := (n - n/2 - 1) * blockSize
	if vss <= fvHeaderLen+storeHeaderLen || uint64(vss-fvHeaderLen) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: variable store size %#x", ErrInvalid, vss)
	}
	vss -= fvHeaderLen

	b := bytes.Repeat([]byte{0xff}, size)
	clear(b[:fvHeaderLen+storeHeaderLen])
	copy(b[16:], systemNvDataFvGUID[:])
	le.PutUint64(b[32:], uint64(size))
	le.PutUint32(b[40:], fvSignature)
	le.PutUint32(b[44:], fvAttributes)
	le.PutUint16(b[48:], fvHeaderLen)
	b[55] = fvRevision
	le.PutUint32(b[56:], uint32(n))
	le.PutUint32(b[60:], uint32(blockSize))
	le.PutUint16(b[50:], -checksum16(b[:fvHeaderLen]))

	sh := b[fvHeaderLen:]
	copy(sh, authVariableGUID[:])
	le.PutUint32(sh[16:], uint32(vss))
	sh[20] = storeFormatted
	sh[21] = storeHealthy
	return b, nil
}

// IsErased reports whether region is all 0xff.
func IsErased(region []byte) bool {
	for _, b := range region {
		if b != 0xff {
			return false
		}
	}
	return true
}

// Bytes returns the region contents, same length as the parsed region.
func (s *Store) Bytes() []byte { return s.region }

// Free returns the bytes left behind the last record, without reclaim.
func (s *Store) Free() int { return s.end - s.free }
