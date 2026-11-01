package efivars

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Test-only model of coreboot's efi_fv_get_option() (src/drivers/efi/efivars.c):
// validate_fv_header + validate_variable_store_header + walk_variables with
// find_and_copy. Written independently of the package's parser on purpose, with
// literal offsets, so both can be checked against each other.

var (
	errOracleNotFound = errors.New("oracle: option not found")
	errOracleCorrupt  = errors.New("oracle: store invalid")
)

func corebootGetOption(region []byte, guid GUID, name string) ([]byte, error) {
	u16 := func(o int) int { return int(binary.LittleEndian.Uint16(region[o:])) }
	u32 := func(o int) uint64 { return uint64(binary.LittleEndian.Uint32(region[o:])) }
	u64 := func(o int) uint64 { return binary.LittleEndian.Uint64(region[o:]) }

	if len(region) < 0x48 {
		return nil, errOracleCorrupt
	}
	fvLength, headerLength := u64(32), u16(48)
	if region[55] != 2 || u32(40) != 0x4856465f || fvLength > uint64(len(region)) ||
		headerLength < 0x48 || uint64(headerLength) > fvLength ||
		fvLength-uint64(headerLength) < 28 || headerLength&1 != 0 {
		return nil, errOracleCorrupt
	}
	if !bytes.Equal(region[16:32], []byte{0x8d, 0x2b, 0xf1, 0xff, 0x96, 0x76, 0x8b, 0x4c,
		0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50}) {
		return nil, errOracleCorrupt
	}
	var sum uint16
	for i := 0; i < headerLength; i += 2 {
		sum += uint16(u16(i))
	}
	if sum != 0 {
		return nil, errOracleCorrupt
	}
	var mapped uint64
	terminated := false
	for o := 56; o <= headerLength-8; o += 8 {
		n, l := u32(o), u32(o+4)
		if n == 0 && l == 0 {
			terminated = true
			break
		}
		if n == 0 || l == 0 {
			return nil, errOracleCorrupt
		}
		mapped += n * l
	}
	if !terminated || mapped != fvLength {
		return nil, errOracleCorrupt
	}

	vs := headerLength
	var auth bool
	switch {
	case bytes.Equal(region[vs:vs+16], []byte{0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43,
		0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92}):
		auth = true
	case bytes.Equal(region[vs:vs+16], []byte{0x16, 0x36, 0xcf, 0xdd, 0x75, 0x32, 0x64, 0x41,
		0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d}):
	default:
		return nil, errOracleCorrupt
	}
	size := u32(vs + 16)
	if size <= 28 || size > fvLength-uint64(headerLength) || region[vs+20] != 0x5a || region[vs+21] != 0xfe {
		return nil, errOracleCorrupt
	}

	pos, end := vs+28, vs+int(size)
	hsz, nameOff, dataOff, guidOff := 32, 8, 12, 16
	if auth {
		hsz, nameOff, dataOff, guidOff = 60, 36, 40, 44
	}
	erased := func(b []byte) bool { return bytes.Count(b, []byte{0xff}) == len(b) }
	want := make([]byte, 0, 2*len(name)+2)
	for i := 0; i < len(name); i++ {
		want = append(want, name[i], 0)
	}
	want = append(want, 0, 0)

	var found []byte
	foundAny, done := false, false
	for {
		rem := end - pos
		if rem < hsz || u16(pos) != 0x55aa {
			if !erased(region[pos:end]) {
				return nil, errOracleCorrupt
			}
			break
		}
		state := region[pos+2]
		switch state {
		case 0xff, 0x7f, 0x3f, 0x3e, 0x3d, 0x3c:
		default:
			return nil, errOracleCorrupt
		}
		ns, ds := u32(pos+nameOff), u32(pos+dataOff)
		vsz := (uint64(hsz) + ns + ds + 3) &^ 3
		if vsz == 0 || vsz > uint64(rem) || ns < 2 || ns%2 != 0 {
			return nil, errOracleCorrupt
		}
		if state != 0xff && state != 0x7f {
			if u16(pos+hsz+int(ns)-2) != 0 {
				return nil, errOracleCorrupt
			}
			if !done && (state == 0x3f || state == 0x3e) &&
				bytes.Equal(region[pos+guidOff:pos+guidOff+16], guid[:]) &&
				bytes.Equal(region[pos+hsz:pos+hsz+int(ns)], want) {
				found = region[pos+hsz+int(ns) : pos+hsz+int(ns)+int(ds)]
				foundAny = true
				done = state == 0x3f
			}
		}
		pos += int(vsz)
		if pos == end {
			break
		}
	}
	if !foundAny {
		return nil, errOracleNotFound
	}
	return bytes.Clone(found), nil
}

// checkOracle asserts coreboot reads each wanted name/value (nil = absent).
func checkOracle(t *testing.T, region []byte, guid GUID, want map[string][]byte) {
	t.Helper()
	for name, w := range want {
		got, err := corebootGetOption(region, guid, name)
		if w == nil {
			if !errors.Is(err, errOracleNotFound) {
				t.Errorf("coreboot oracle %s: got %x, %v; want not found", name, got, err)
			}
			continue
		}
		if err != nil || !bytes.Equal(got, w) {
			t.Errorf("coreboot oracle %s: got %x, %v; want %x", name, got, err, w)
		}
	}
}
