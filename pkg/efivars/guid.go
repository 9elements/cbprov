package efivars

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseGUID parses the canonical text form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
func ParseGUID(s string) (GUID, error) {
	var g GUID
	parts := strings.Split(s, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		return g, fmt.Errorf("invalid GUID %q", s)
	}
	raw, err := hex.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return g, fmt.Errorf("invalid GUID %q: %w", s, err)
	}
	binary.LittleEndian.PutUint32(g[0:], binary.BigEndian.Uint32(raw[0:]))
	binary.LittleEndian.PutUint16(g[4:], binary.BigEndian.Uint16(raw[4:]))
	binary.LittleEndian.PutUint16(g[6:], binary.BigEndian.Uint16(raw[6:]))
	copy(g[8:], raw[8:])
	return g, nil
}

// MustParseGUID is ParseGUID for constants.
func MustParseGUID(s string) GUID {
	g, err := ParseGUID(s)
	if err != nil {
		panic(err)
	}
	return g
}

func (g GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(g[0:]), binary.LittleEndian.Uint16(g[4:]),
		binary.LittleEndian.Uint16(g[6:]), g[8:10], g[10:])
}
