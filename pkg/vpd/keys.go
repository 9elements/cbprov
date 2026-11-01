package vpd

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Encoding is how a key's value is stored.
type Encoding int

const (
	// EncString is printable ASCII without NUL terminator.
	EncString Encoding = iota
	// EncUUID is 16 raw bytes in SMBIOS byte order.
	EncUUID
)

func (e Encoding) String() string {
	return [...]string{"string", "uuid"}[e]
}

// Key describes a VPD key that coreboot copies into SMBIOS.
// coreboot reads all of them from RO_VPD only.
type Key struct {
	Name string
	// SMBIOS is the field the key fills.
	SMBIOS string
	// Kconfig enables reading the key, without CONFIG_ prefix.
	Kconfig string
	// MaxLen is the buffer size coreboot reads into, including the NUL;
	// longer strings are truncated. For EncUUID it is the exact value size.
	MaxLen   int
	Encoding Encoding
	// Proposed keys are not read by upstream coreboot yet and need a patch.
	Proposed bool
}

const (
	defaultSerialSize = 64 // CONFIG_SMBIOS_SERIAL_SIZE
	defaultDataSize   = 64 // CONFIG_SMBIOS_SYSTEM_DATA_SIZE
	uuidSize          = 16
)

var keys = []Key{
	{Name: "serial_number", SMBIOS: "Type 1 Serial Number", Kconfig: "SMBIOS_SERIAL_FROM_VPD", MaxLen: defaultSerialSize},
	{Name: "mlb_serial_number", SMBIOS: "Type 2 Serial Number", Kconfig: "SMBIOS_SERIAL_FROM_VPD", MaxLen: defaultSerialSize},
	{Name: "system_uuid", SMBIOS: "Type 1 UUID", Kconfig: "SMBIOS_UUID_FROM_VPD", MaxLen: uuidSize, Encoding: EncUUID},
	{Name: "system_product_name", SMBIOS: "Type 1 Product Name", Kconfig: "SMBIOS_SYSTEM_DATA_FROM_VPD", MaxLen: defaultDataSize},
	{Name: "system_sku", SMBIOS: "Type 1 SKU Number", Kconfig: "SMBIOS_SYSTEM_DATA_FROM_VPD", MaxLen: defaultDataSize},
	{Name: "system_family", SMBIOS: "Type 1 Family", Kconfig: "SMBIOS_SYSTEM_DATA_FROM_VPD", MaxLen: defaultDataSize},

	{Name: "system_manufacturer", SMBIOS: "Type 1 Manufacturer", Kconfig: "SMBIOS_SYSTEM_DATA_FROM_VPD", MaxLen: defaultDataSize, Proposed: true},
	{Name: "system_version", SMBIOS: "Type 1 Version", Kconfig: "SMBIOS_SYSTEM_DATA_FROM_VPD", MaxLen: defaultDataSize, Proposed: true},
	{Name: "mainboard_manufacturer", SMBIOS: "Type 2 Manufacturer", Kconfig: "SMBIOS_MAINBOARD_DATA_FROM_VPD", MaxLen: defaultDataSize, Proposed: true},
	{Name: "mainboard_product_name", SMBIOS: "Type 2 Product Name", Kconfig: "SMBIOS_MAINBOARD_DATA_FROM_VPD", MaxLen: defaultDataSize, Proposed: true},
	{Name: "mainboard_version", SMBIOS: "Type 2 Version", Kconfig: "SMBIOS_MAINBOARD_DATA_FROM_VPD", MaxLen: defaultDataSize, Proposed: true},
	// smbios_mainboard_asset_tag() feeds both tables.
	{Name: "asset_tag", SMBIOS: "Type 2 Asset Tag, Type 3 Asset Tag Number", Kconfig: "SMBIOS_MAINBOARD_DATA_FROM_VPD", MaxLen: defaultDataSize, Proposed: true},
	{Name: "chassis_serial_number", SMBIOS: "Type 3 Serial Number", Kconfig: "SMBIOS_SERIAL_FROM_VPD", MaxLen: defaultSerialSize, Proposed: true},
}

// Keys returns the SMBIOS key catalogue: keys coreboot reads today, then proposed ones.
func Keys() []Key { return append([]Key(nil), keys...) }

// LookupKey returns the catalogue entry for name.
func LookupKey(name string) (Key, bool) {
	for _, k := range keys {
		if k.Name == name {
			return k, true
		}
	}
	return Key{}, false
}

// ParseValue converts command-line text into the stored value of key.
// Catalogue string keys must be printable ASCII shorter than MaxLen;
// system_uuid takes canonical UUID text. Unknown keys store text verbatim.
func ParseValue(key, text string) ([]byte, error) {
	if err := CheckKey(key); err != nil {
		return nil, err
	}
	k, ok := LookupKey(key)
	if !ok {
		return []byte(text), nil
	}
	switch k.Encoding {
	case EncUUID:
		u, err := parseUUID(text)
		if err != nil {
			return nil, fmt.Errorf("vpd: %s: %w", key, err)
		}
		return u, nil
	default:
		if i := strings.IndexFunc(text, func(r rune) bool { return r < 0x20 || r > 0x7e }); i >= 0 {
			return nil, fmt.Errorf("vpd: %s: non-printable or non-ASCII character at position %d", key, i)
		}
		if len(text) > k.MaxLen-1 {
			return nil, fmt.Errorf("vpd: %s: %d characters, coreboot reads at most %d (%d incl. NUL)",
				key, len(text), k.MaxLen-1, k.MaxLen)
		}
		return []byte(text), nil
	}
}

// FormatValue renders a stored value for display; it is the inverse of
// ParseValue. Values that do not fit the key's encoding are shown as hex.
func FormatValue(key string, v []byte) string {
	if k, ok := LookupKey(key); ok && k.Encoding == EncUUID {
		if len(v) == uuidSize {
			return formatUUID(v)
		}
		return hex.EncodeToString(v)
	}
	if isPrintable(v) {
		return string(v)
	}
	return hex.EncodeToString(v)
}

func isPrintable(v []byte) bool {
	for _, c := range v {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// smbiosOrder maps stored byte i to canonical byte smbiosOrder[i]: the first
// three UUID fields are little-endian (SMBIOS 7.2.1), the rest as written.
var smbiosOrder = [uuidSize]int{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15}

func parseUUID(s string) ([]byte, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, fmt.Errorf("%q is not a UUID (want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)", s)
	}
	canon, err := hex.DecodeString(s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:])
	if err != nil {
		return nil, fmt.Errorf("%q is not a UUID: %w", s, err)
	}
	out := make([]byte, uuidSize)
	for i, j := range smbiosOrder {
		out[i] = canon[j]
	}
	return out, nil
}

func formatUUID(v []byte) string {
	canon := make([]byte, uuidSize)
	for i, j := range smbiosOrder {
		canon[j] = v[i]
	}
	h := hex.EncodeToString(canon)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
