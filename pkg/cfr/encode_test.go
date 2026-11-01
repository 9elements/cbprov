package cfr

import "encoding/binary"

// Test-only encoder mirroring src/drivers/option/cfr.c and src/lib/coreboot_table.c.

type tOpt struct {
	tag                       uint32
	id, dep                   uint64
	flags                     uint32
	name, ui, help, defStr    string
	def, min, max, step, disp uint32
	deps                      []uint32
	enums                     []EnumValue
	children                  []tOpt
}

const padByte = 0xa5 // cfr.c leaves alignment padding uninitialised

func u32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }
func u64(b []byte, v uint64) []byte { return binary.LittleEndian.AppendUint64(b, v) }

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, padByte)
	}
	return b
}

func setSize(b []byte, start int) {
	binary.LittleEndian.PutUint32(b[start+4:], uint32(len(b)-start))
}

// write_cfr_varchar
func encVarchar(b []byte, tag uint32, s string) []byte {
	start := len(b)
	b = u32(b, tag)
	b = u32(b, 0)
	b = u32(b, uint32(len(s)+1))
	b = append(b, s...)
	b = pad4(append(b, 0))
	setSize(b, start)
	return b
}

// sm_write_dep_values
func encDeps(b []byte, deps []uint32) []byte {
	if len(deps) == 0 {
		return b
	}
	start := len(b)
	b = u32(b, tagDepValues)
	b = u32(b, 0)
	b = u32(b, uint32(4*len(deps)))
	for _, d := range deps {
		b = u32(b, d)
	}
	setSize(b, start)
	return b
}

func encHelp(b []byte, s string) []byte {
	if s == "" {
		return b
	}
	return encVarchar(b, tagHelpText, s)
}

func encOpt(b []byte, o tOpt) []byte {
	start := len(b)
	flags := o.flags
	if flags&(FlagInactive|FlagVolatile) != 0 {
		flags |= FlagReadOnly
	}
	b = u32(b, o.tag)
	b = u32(b, 0)
	b = u64(b, o.id)
	b = u64(b, o.dep)
	b = u32(b, flags)
	switch o.tag {
	case tagEnum, tagNumber, tagBool: // write_numeric_option
		lo, hi := o.min, o.max
		if lo > hi {
			lo = 0
		}
		if o.min == 0 && o.max == 0 {
			hi = 0xffffffff
		}
		for _, v := range []uint32{o.def, lo, hi, o.step, o.disp} {
			b = u32(b, v)
		}
		b = encVarchar(b, tagOptName, o.name)
		b = encVarchar(b, tagUIName, o.ui)
		b = encHelp(b, o.help)
		b = encDeps(b, o.deps)
		if o.tag == tagEnum {
			for _, e := range o.enums {
				es := len(b)
				b = u32(b, tagEnumValue)
				b = u32(b, 0)
				b = u32(b, e.Value)
				b = encVarchar(b, tagUIName, e.UIName)
				setSize(b, es)
			}
		}
	case tagVarchar:
		b = encVarchar(b, tagDefValue, o.defStr)
		b = encVarchar(b, tagOptName, o.name)
		b = encVarchar(b, tagUIName, o.ui)
		b = encHelp(b, o.help)
		b = encDeps(b, o.deps)
	case tagComment:
		b = encVarchar(b, tagUIName, o.ui)
		b = encHelp(b, o.help)
		b = encDeps(b, o.deps)
	case tagForm:
		b = encVarchar(b, tagUIName, o.ui)
		b = encDeps(b, o.deps)
		for _, c := range o.children {
			b = encOpt(b, c)
		}
	}
	setSize(b, start)
	return b
}

// cfr_write_setup_menu
func encRoot(forms ...tOpt) []byte {
	b := u32(nil, lbTagCFR)
	b = u32(b, 0)
	b = u32(b, Version)
	b = u32(b, 0)
	for _, f := range forms {
		b = encOpt(b, f)
	}
	setSize(b, 0)
	return fixCRC(b)
}

func fixCRC(b []byte) []byte {
	if len(b) < rootHdrSize {
		return b
	}
	end := min(int(binary.LittleEndian.Uint32(b[4:])), len(b))
	if end < rootHdrSize {
		return b
	}
	binary.LittleEndian.PutUint32(b[12:], crc32(b[rootHdrSize:end]))
	return b
}

func lbRecord(tag uint32, payload []byte) []byte {
	b := u32(nil, tag)
	b = u32(b, 0)
	b = pad4(append(b, payload...))
	setSize(b, 0)
	return b
}

// lb_table_init + lb_table_fini
func encTable(entries ...[]byte) []byte {
	var table []byte
	for _, e := range entries {
		table = append(table, e...)
	}
	h := append([]byte("LBIO"), make([]byte, 20)...)
	binary.LittleEndian.PutUint32(h[4:], lbHeaderSize)
	binary.LittleEndian.PutUint32(h[12:], uint32(len(table)))
	binary.LittleEndian.PutUint32(h[16:], uint32(ipchksum(table)))
	binary.LittleEndian.PutUint32(h[20:], uint32(len(entries)))
	binary.LittleEndian.PutUint32(h[8:], uint32(ipchksum(h)))
	return append(h, table...)
}

func sampleOpts() []tOpt {
	return []tOpt{
		{tag: tagForm, id: 1, ui: "System", children: []tOpt{
			{tag: tagBool, id: 2, name: "s3_enable", ui: "S3 support", def: 1},
			{tag: tagEnum, id: 3, name: "power_on_after_fail", ui: "Power on after failure",
				help: "What to do after power loss", def: 2, flags: FlagRuntime,
				enums: []EnumValue{{0, "Off"}, {1, "On"}, {2, "Keep"}}},
			{tag: tagNumber, id: 4, dep: 2, deps: []uint32{1}, name: "fan_threshold", ui: "Fan threshold",
				def: 0x40, min: 0x10, max: 0x80, step: 8, disp: DisplayHex},
			{tag: tagVarchar, id: 5, name: "hostname", ui: "Hostname", defStr: "coreboot"},
			{tag: tagComment, id: 6, ui: "Board info", help: "Read-only data"},
			{tag: tagForm, id: 7, dep: 3, deps: []uint32{1, 2}, ui: "Advanced", children: []tOpt{
				{tag: tagBool, id: 8, name: "me_state", ui: "ME state", flags: FlagVolatile},
				{tag: tagNumber, id: 9, name: "boot_delay", ui: "Boot delay", def: 5},
			}},
		}},
		{tag: tagForm, id: 10, ui: "Security", children: []tOpt{
			{tag: tagBool, id: 11, name: "lock", ui: "Lock", flags: FlagLockAtBoot | FlagSuppress},
		}},
	}
}

func sampleBlob() []byte { return encRoot(sampleOpts()...) }

func sampleSchema() *Schema {
	return &Schema{Forms: []*Option{
		{Kind: KindForm, ObjectID: 1, UIName: "System", Options: []*Option{
			{Kind: KindBool, ObjectID: 2, Name: "s3_enable", UIName: "S3 support", Default: 1, Max: 0xffffffff},
			{Kind: KindEnum, ObjectID: 3, Name: "power_on_after_fail", UIName: "Power on after failure",
				HelpText: "What to do after power loss", Default: 2, Flags: FlagRuntime, Max: 0xffffffff,
				EnumValues: []EnumValue{{0, "Off"}, {1, "On"}, {2, "Keep"}}},
			{Kind: KindNumber, ObjectID: 4, DependencyID: 2, DepValues: []uint32{1}, Name: "fan_threshold",
				UIName: "Fan threshold", Default: 0x40, Min: 0x10, Max: 0x80, Step: 8, DisplayFlags: DisplayHex},
			{Kind: KindVarchar, ObjectID: 5, Name: "hostname", UIName: "Hostname", DefaultStr: "coreboot"},
			{Kind: KindComment, ObjectID: 6, UIName: "Board info", HelpText: "Read-only data"},
			{Kind: KindForm, ObjectID: 7, DependencyID: 3, DepValues: []uint32{1, 2}, UIName: "Advanced", Options: []*Option{
				{Kind: KindBool, ObjectID: 8, Name: "me_state", UIName: "ME state", Flags: FlagVolatile | FlagReadOnly, Max: 0xffffffff},
				{Kind: KindNumber, ObjectID: 9, Name: "boot_delay", UIName: "Boot delay", Default: 5, Max: 0xffffffff},
			}},
		}},
		{Kind: KindForm, ObjectID: 10, UIName: "Security", Options: []*Option{
			{Kind: KindBool, ObjectID: 11, Name: "lock", UIName: "Lock", Flags: FlagLockAtBoot | FlagSuppress, Max: 0xffffffff},
		}},
	}}
}
