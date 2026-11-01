package cfr

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// enum cfr_tags
const (
	tagForm        = 1
	tagEnumValue   = 2
	tagEnum        = 3
	tagNumber      = 4
	tagBool        = 5
	tagVarchar     = 6
	tagOptName     = 7
	tagUIName      = 8
	tagHelpText    = 9
	tagDefValue    = 10
	tagComment     = 11
	tagDepValues   = 12
	lbTagForward   = 0x11
	lbTagCFR       = 0x47 // LB_TAG_CFR_ROOT
	recHdrSize     = 8    // struct lb_record / lb_cfr_header
	rootHdrSize    = 16   // struct lb_cfr
	optHdrSize     = 28   // form, varchar, comment
	numericHdrSize = 48   // struct lb_cfr_numeric_option
	varbinHdrSize  = 12   // struct lb_cfr_varbinary
	enumValueSize  = 12   // struct lb_cfr_enum_value
	maxDepth       = 32
)

var le = binary.LittleEndian

// Parse parses a raw LB_TAG_CFR record (header included). Bytes past the
// record's size are ignored.
func Parse(b []byte) (*Schema, error) {
	if len(b) < rootHdrSize {
		return nil, fmt.Errorf("cfr: %d bytes, need at least %d", len(b), rootHdrSize)
	}
	if tag := le.Uint32(b); tag != lbTagCFR {
		return nil, fmt.Errorf("cfr: root tag 0x%x, want 0x%x", tag, lbTagCFR)
	}
	size := le.Uint32(b[4:])
	if size < rootHdrSize || uint64(size) > uint64(len(b)) {
		return nil, fmt.Errorf("cfr: root size %d out of bounds (have %d bytes)", size, len(b))
	}
	s := &Schema{Version: le.Uint32(b[8:])}
	if s.Version != Version {
		return nil, fmt.Errorf("cfr: unsupported version 0x%x", s.Version)
	}
	if want, got := le.Uint32(b[12:]), crc32(b[rootHdrSize:size]); want != got {
		return nil, fmt.Errorf("cfr: checksum 0x%08x, computed 0x%08x", want, got)
	}
	err := records(b[rootHdrSize:size], rootHdrSize, func(tag uint32, rec []byte, off int) error {
		switch tag {
		case tagForm:
			f, err := parseOption(tag, rec, off, 1)
			if err != nil {
				return err
			}
			s.Forms = append(s.Forms, f)
			return nil
		case tagEnum, tagNumber, tagBool, tagVarchar, tagComment,
			tagEnumValue, tagOptName, tagUIName, tagHelpText, tagDefValue, tagDepValues:
			return fmt.Errorf("cfr: tag %d at offset %d not allowed at top level", tag, off)
		}
		return nil // unknown tag: skip
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// records walks consecutive tag/size records in b; base is b's offset in the root record.
func records(b []byte, base int, fn func(tag uint32, rec []byte, off int) error) error {
	for off := 0; off < len(b); {
		if len(b)-off < recHdrSize {
			return fmt.Errorf("cfr: truncated record header at offset %d", base+off)
		}
		tag, size := le.Uint32(b[off:]), le.Uint32(b[off+4:])
		if size < recHdrSize || uint64(size) > uint64(len(b)-off) {
			return fmt.Errorf("cfr: record tag %d at offset %d: size %d out of bounds", tag, base+off, size)
		}
		if err := fn(tag, b[off:off+int(size)], base+off); err != nil {
			return err
		}
		off += int(size)
	}
	return nil
}

func parseOption(tag uint32, rec []byte, off, depth int) (*Option, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("cfr: forms nested deeper than %d at offset %d", maxDepth, off)
	}
	o := &Option{}
	hdr := optHdrSize
	switch tag {
	case tagForm:
		o.Kind = KindForm
	case tagEnum:
		o.Kind, hdr = KindEnum, numericHdrSize
	case tagNumber:
		o.Kind, hdr = KindNumber, numericHdrSize
	case tagBool:
		o.Kind, hdr = KindBool, numericHdrSize
	case tagVarchar:
		o.Kind = KindVarchar
	case tagComment:
		o.Kind = KindComment
	}
	if len(rec) < hdr {
		return nil, fmt.Errorf("cfr: %s record at offset %d: size %d < header %d", o.Kind, off, len(rec), hdr)
	}
	o.ObjectID = le.Uint64(rec[8:])
	o.DependencyID = le.Uint64(rec[16:])
	o.Flags = le.Uint32(rec[24:])
	if hdr == numericHdrSize {
		o.Default = le.Uint32(rec[28:])
		o.Min = le.Uint32(rec[32:])
		o.Max = le.Uint32(rec[36:])
		o.Step = le.Uint32(rec[40:])
		o.DisplayFlags = le.Uint32(rec[44:])
	}

	seen := map[uint32]bool{}
	err := records(rec[hdr:], off+hdr, func(ct uint32, c []byte, coff int) error {
		if !childAllowed(tag, ct) {
			return fmt.Errorf("cfr: tag %d at offset %d not allowed in %s record", ct, coff, o.Kind)
		}
		switch ct {
		case tagOptName, tagUIName, tagHelpText, tagDefValue, tagDepValues:
			if seen[ct] {
				return fmt.Errorf("cfr: duplicate tag %d at offset %d", ct, coff)
			}
			seen[ct] = true
			d, err := varbinary(c, coff)
			if err != nil {
				return err
			}
			switch ct {
			case tagOptName:
				o.Name = cstring(d)
			case tagUIName:
				o.UIName = cstring(d)
			case tagHelpText:
				o.HelpText = cstring(d)
			case tagDefValue:
				o.DefaultStr = cstring(d)
			case tagDepValues:
				if len(d)%4 != 0 {
					return fmt.Errorf("cfr: dependency values at offset %d: length %d not a multiple of 4", coff, len(d))
				}
				o.DepValues = make([]uint32, len(d)/4)
				for i := range o.DepValues {
					o.DepValues[i] = le.Uint32(d[4*i:])
				}
			}
		case tagEnumValue:
			e, err := parseEnumValue(c, coff)
			if err != nil {
				return err
			}
			o.EnumValues = append(o.EnumValues, e)
		case tagForm, tagEnum, tagNumber, tagBool, tagVarchar, tagComment:
			child, err := parseOption(ct, c, coff, depth+1)
			if err != nil {
				return err
			}
			o.Options = append(o.Options, child)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if o.Name == "" && (o.Kind == KindEnum || o.Kind == KindNumber || o.Kind == KindBool || o.Kind == KindVarchar) {
		return nil, fmt.Errorf("cfr: %s record at offset %d has no opt_name", o.Kind, off)
	}
	return o, nil
}

// childAllowed reports whether a known child tag may appear in a parent record;
// unknown tags are allowed (and skipped) for forward compatibility.
func childAllowed(parent, child uint32) bool {
	switch child {
	case tagUIName, tagDepValues:
		return true
	case tagOptName:
		return parent == tagEnum || parent == tagNumber || parent == tagBool || parent == tagVarchar
	case tagHelpText:
		return parent != tagForm
	case tagDefValue:
		return parent == tagVarchar
	case tagEnumValue:
		return parent == tagEnum
	case tagForm, tagEnum, tagNumber, tagBool, tagVarchar, tagComment:
		return parent == tagForm
	}
	return true
}

func parseEnumValue(rec []byte, off int) (EnumValue, error) {
	if len(rec) < enumValueSize {
		return EnumValue{}, fmt.Errorf("cfr: enum value at offset %d: size %d < %d", off, len(rec), enumValueSize)
	}
	e := EnumValue{Value: le.Uint32(rec[8:])}
	seen := false
	err := records(rec[enumValueSize:], off+enumValueSize, func(ct uint32, c []byte, coff int) error {
		if ct != tagUIName {
			return nil
		}
		if seen {
			return fmt.Errorf("cfr: duplicate enum ui_name at offset %d", coff)
		}
		seen = true
		d, err := varbinary(c, coff)
		e.UIName = cstring(d)
		return err
	})
	return e, err
}

func varbinary(rec []byte, off int) ([]byte, error) {
	if len(rec) < varbinHdrSize {
		return nil, fmt.Errorf("cfr: varbinary at offset %d: size %d < %d", off, len(rec), varbinHdrSize)
	}
	n := le.Uint32(rec[8:])
	if uint64(n) > uint64(len(rec)-varbinHdrSize) {
		return nil, fmt.Errorf("cfr: varbinary at offset %d: data length %d exceeds record", off, n)
	}
	return rec[varbinHdrSize : varbinHdrSize+int(n)], nil
}

// cstring returns d up to its first NUL; data_length counts the terminator.
func cstring(d []byte) string {
	if i := bytes.IndexByte(d, 0); i >= 0 {
		d = d[:i]
	}
	return string(d)
}

// crc32Table is for coreboot's crc32_byte: MSB-first, poly 0x04C11DB7, init 0,
// no final XOR, which hash/crc32 (reflected only) can't compute.
var crc32Table = func() (t [256]uint32) {
	for i := range t {
		c := uint32(i) << 24
		for range 8 {
			if c&0x80000000 != 0 {
				c = c<<1 ^ 0x04C11DB7
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

func crc32(b []byte) uint32 {
	var c uint32
	for _, x := range b {
		c = c<<8 ^ crc32Table[byte(c>>24)^x]
	}
	return c
}
