package efivars

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

var le = binary.LittleEndian

// On-flash layout (EDK2 PiFirmwareVolume.h / VariableFormat.h, pack(1)).
const (
	fvHeaderLen    = 0x48 // EFI_FIRMWARE_VOLUME_HEADER with one block map entry + terminator
	fvSignature    = 0x4856465f
	fvRevision     = 2
	fvAttributes   = 0xe36 // READ_ENABLED_CAP|READ_STATUS|WRITE_ENABLED_CAP|WRITE_STATUS|STICKY_WRITE|MEMORY_MAPPED|ERASE_POLARITY
	fvBlockMapOff  = 56
	storeHeaderLen = 28
	storeFormatted = 0x5a
	storeHealthy   = 0xfe

	plainHeaderLen = 32
	authHeaderLen  = 60
	headerAlign    = 4
	startID        = 0x55aa

	stateHeaderValidOnly     = 0x7f
	stateAdded               = 0x3f
	stateInDeletedTransition = 0xfe
	stateDeleted             = 0xfd

	stateTransition   = stateAdded & stateInDeletedTransition                // 0x3e
	stateDeletedFinal = stateAdded & stateInDeletedTransition & stateDeleted // 0x3c
)

// Attribute bits beyond the defaults that are accepted on Set.
const (
	attrHardwareErrorRecord = 0x8
	attrAuthWrite           = 0x10 | 0x20 // (TIME_BASED_)AUTHENTICATED_WRITE_ACCESS
	attrAppendWrite         = 0x40
)

var (
	systemNvDataFvGUID = MustParseGUID("fff12b8d-7696-4c8b-a985-2747075b4f50")
	variableGUID       = MustParseGUID("ddcf3616-3275-4164-98b6-fe85707ffe7d")
	authVariableGUID   = MustParseGUID("aaf32c78-947b-439a-a180-2e144ec37792")
)

// validState lists the states coreboot's walker accepts; anything else makes
// coreboot reject the whole store.
func validState(s byte) bool {
	switch s {
	case 0xff, stateHeaderValidOnly, stateAdded, stateTransition,
		stateAdded & stateDeleted, stateDeletedFinal:
		return true
	}
	return false
}

func alignUp(n int) int { return (n + headerAlign - 1) &^ (headerAlign - 1) }

// encodeName returns the NUL-terminated UTF-16LE form of name.
func encodeName(name string) ([]byte, error) {
	if name == "" || !utf8.ValidString(name) {
		return nil, fmt.Errorf("%w: variable name %q", ErrInvalid, name)
	}
	var units []uint16
	for _, r := range name {
		if r == 0 {
			return nil, fmt.Errorf("%w: variable name contains NUL", ErrInvalid)
		}
		units = utf16.AppendRune(units, r)
	}
	b := make([]byte, 2*(len(units)+1))
	for i, u := range units {
		le.PutUint16(b[2*i:], u)
	}
	return b, nil
}

// decodeName decodes a UTF-16LE name, stopping at the first NUL.
func decodeName(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := le.Uint16(b[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// header is a decoded variable header; offsets differ between the plain and
// authenticated formats.
type header struct {
	state    byte
	attrs    uint32
	nameSize uint32
	dataSize uint32
	guid     GUID
}

func readHeader(b []byte, auth bool) header {
	h := header{state: b[2], attrs: le.Uint32(b[4:])}
	if auth {
		h.nameSize, h.dataSize = le.Uint32(b[36:]), le.Uint32(b[40:])
		copy(h.guid[:], b[44:60])
	} else {
		h.nameSize, h.dataSize = le.Uint32(b[8:]), le.Uint32(b[12:])
		copy(h.guid[:], b[16:32])
	}
	return h
}

// encodeRecord builds a VAR_ADDED record like EDK2's UpdateVariable does:
// Reserved, MonotonicCount, TimeStamp and PubKeyIndex are zero.
func encodeRecord(auth bool, guid GUID, rawName []byte, attrs uint32, data []byte) []byte {
	hl := plainHeaderLen
	if auth {
		hl = authHeaderLen
	}
	b := make([]byte, hl+len(rawName)+len(data))
	le.PutUint16(b[0:], startID)
	b[2] = stateAdded
	le.PutUint32(b[4:], attrs)
	if auth {
		le.PutUint32(b[36:], uint32(len(rawName)))
		le.PutUint32(b[40:], uint32(len(data)))
		copy(b[44:], guid[:])
	} else {
		le.PutUint32(b[8:], uint32(len(rawName)))
		le.PutUint32(b[12:], uint32(len(data)))
		copy(b[16:], guid[:])
	}
	copy(b[hl:], rawName)
	copy(b[hl+len(rawName):], data)
	return b
}

func checksum16(b []byte) uint16 {
	var sum uint16
	for i := 0; i+1 < len(b); i += 2 {
		sum += le.Uint16(b[i:])
	}
	return sum
}
