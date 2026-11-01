// Package options reads and changes coreboot option values stored as EFI
// variables in SMMSTORE, using a CFR schema for names, types and defaults.
package options

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/9elements/cbprov/pkg/cfr"
	"github.com/9elements/cbprov/pkg/efivars"
)

// Region is the FMAP region holding the variable store.
const Region = "SMMSTORE"

// DefaultBlockSize is CONFIG_SMMSTORE_BLOCK_SIZE's default.
const DefaultBlockSize = 64 * 1024

// State says where an option's value comes from.
type State string

const (
	StateSet     State = "set"     // stored in SMMSTORE
	StateDefault State = "default" // not stored; coreboot uses the CFR default
	StateRaw     State = "raw"     // stored, but not described by the schema
)

// Value is one option as shown to the user.
type Value struct {
	Name       string   `json:"name"`
	UIName     string   `json:"ui_name,omitempty"`
	Kind       string   `json:"kind"`
	Value      uint32   `json:"value"`
	Display    string   `json:"display"`
	Default    *uint32  `json:"default,omitempty"`
	DefaultStr string   `json:"default_display,omitempty"`
	State      State    `json:"state"`
	Flags      []string `json:"flags,omitempty"`
	Choices    []string `json:"choices,omitempty"`
	Help       string   `json:"help,omitempty"`
}

// Set is the option view of one image. Changes stay in memory until the
// caller copies Bytes() back into the region.
type Set struct {
	region    []byte
	blockSize int
	store     *efivars.Store // nil while the region is erased
	schema    *cfr.Schema
}

// Load parses the SMMSTORE region. schema may be nil (raw mode).
func Load(region []byte, blockSize int, schema *cfr.Schema) (*Set, error) {
	if blockSize <= 0 {
		blockSize = DefaultBlockSize
	}
	s := &Set{region: region, blockSize: blockSize, schema: schema}
	if efivars.IsErased(region) {
		return s, nil
	}
	st, err := efivars.Parse(region)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Region, err)
	}
	s.store = st
	return s, nil
}

// Schema returns the schema in use, or nil.
func (s *Set) Schema() *cfr.Schema { return s.schema }

// Erased reports whether the store is still erased (never initialised).
func (s *Set) Erased() bool { return s.store == nil }

// Bytes returns the region contents including all changes.
func (s *Set) Bytes() []byte {
	if s.store == nil {
		return s.region
	}
	return s.store.Bytes()
}

func (s *Set) stored(name string) (uint32, bool, error) {
	if s.store == nil {
		return 0, false, nil
	}
	v, ok := s.store.Get(efivars.CorebootNvDataGUID, name)
	if !ok {
		return 0, false, nil
	}
	// coreboot's efi_option_get_uint() rejects any size but 4 and falls back to the default.
	if len(v.Data) != 4 {
		return 0, false, fmt.Errorf("option %s: stored size %d, coreboot expects 4", name, len(v.Data))
	}
	return binary.LittleEndian.Uint32(v.Data), true, nil
}

// List returns all schema options followed by stored variables the schema
// does not describe.
func (s *Set) List() ([]Value, error) {
	var out []Value
	seen := map[string]bool{}
	if s.schema != nil {
		for _, o := range s.schema.Options() {
			if o.Kind == cfr.KindForm || o.Kind == cfr.KindComment || o.Name == "" {
				continue
			}
			v, err := s.describe(o)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			seen[o.Name] = true
		}
	}
	if s.store != nil {
		var raw []Value
		for _, v := range s.store.Variables() {
			if v.GUID != efivars.CorebootNvDataGUID || seen[v.Name] {
				continue
			}
			rv := Value{Name: v.Name, Kind: "raw", State: StateRaw}
			if len(v.Data) == 4 {
				rv.Value = binary.LittleEndian.Uint32(v.Data)
				rv.Display = strconv.FormatUint(uint64(rv.Value), 10)
			} else {
				rv.Display = fmt.Sprintf("<%d bytes>", len(v.Data))
			}
			raw = append(raw, rv)
		}
		sort.Slice(raw, func(i, j int) bool { return raw[i].Name < raw[j].Name })
		out = append(out, raw...)
	}
	return out, nil
}

// Get returns one option by variable name.
func (s *Set) Get(name string) (Value, error) {
	if s.schema != nil {
		if o, ok := s.schema.Lookup(name); ok {
			return s.describe(o)
		}
	}
	all, err := s.List()
	if err != nil {
		return Value{}, err
	}
	for _, v := range all {
		if v.Name == name {
			return v, nil
		}
	}
	return Value{}, fmt.Errorf("option %s: not in schema and not stored", name)
}

func (s *Set) describe(o *cfr.Option) (Value, error) {
	v := Value{Name: o.Name, UIName: o.UIName, Kind: o.Kind.String(), Help: o.HelpText, Flags: flagNames(o.Flags)}
	if o.Kind == cfr.KindVarchar {
		v.State = StateDefault
		v.Display = o.DefaultStr
		v.DefaultStr = o.DefaultStr
		return v, nil
	}
	def := o.Default
	v.Default = &def
	v.DefaultStr = display(o, def)
	for _, e := range o.EnumValues {
		v.Choices = append(v.Choices, e.UIName)
	}
	if o.Kind == cfr.KindBool {
		v.Choices = []string{"Disabled", "Enabled"}
	}
	cur, ok, err := s.stored(o.Name)
	if err != nil {
		return v, err
	}
	if ok {
		v.Value, v.State = cur, StateSet
	} else {
		v.Value, v.State = def, StateDefault
	}
	v.Display = display(o, v.Value)
	return v, nil
}

// SetValue parses text for the named option and stores it.
func (s *Set) SetValue(name, text string) error {
	var val uint32
	if o, ok := s.lookup(name); ok {
		if o.Kind == cfr.KindVarchar {
			return fmt.Errorf("option %s: string options are not supported by coreboot's EFI option backend", name)
		}
		if o.Kind == cfr.KindForm || o.Kind == cfr.KindComment {
			return fmt.Errorf("option %s: is a %s, not a value", name, o.Kind)
		}
		v, err := parse(o, text)
		if err != nil {
			return fmt.Errorf("option %s: %w", name, err)
		}
		if err := o.Validate(v); err != nil {
			return fmt.Errorf("option %w", err)
		}
		val = v
	} else {
		if s.schema != nil {
			return fmt.Errorf("option %s: not in schema (use --raw to write it anyway)", name)
		}
		v, err := parseUint(text)
		if err != nil {
			return fmt.Errorf("option %s: no schema, value must be a number: %w", name, err)
		}
		val = v
	}
	return s.SetRaw(name, val)
}

// SetRaw stores a value without schema checks.
func (s *Set) SetRaw(name string, val uint32) error {
	if err := s.ensureStore(); err != nil {
		return err
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], val)
	return s.store.Set(efivars.CorebootNvDataGUID, name, efivars.DefaultAttributes, b[:])
}

// Reset deletes the stored value so coreboot falls back to the default.
func (s *Set) Reset(name string) (bool, error) {
	if s.store == nil {
		return false, nil
	}
	return s.store.Delete(efivars.CorebootNvDataGUID, name)
}

// ResetAll deletes every coreboot option variable; other GUIDs stay.
func (s *Set) ResetAll() (int, error) {
	if s.store == nil {
		return 0, nil
	}
	n := 0
	for _, v := range s.store.Variables() {
		if v.GUID != efivars.CorebootNvDataGUID {
			continue
		}
		if _, err := s.store.Delete(v.GUID, v.Name); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *Set) lookup(name string) (*cfr.Option, bool) {
	if s.schema == nil {
		return nil, false
	}
	return s.schema.Lookup(name)
}

func (s *Set) ensureStore() error {
	if s.store != nil {
		return nil
	}
	fresh, err := efivars.Format(len(s.region), s.blockSize)
	if err != nil {
		return fmt.Errorf("initialising %s: %w", Region, err)
	}
	st, err := efivars.Parse(fresh)
	if err != nil {
		return fmt.Errorf("initialising %s: %w", Region, err)
	}
	s.store = st
	return nil
}

func parse(o *cfr.Option, text string) (uint32, error) {
	t := strings.TrimSpace(text)
	switch o.Kind {
	case cfr.KindBool:
		switch strings.ToLower(t) {
		case "1", "true", "on", "yes", "enable", "enabled":
			return 1, nil
		case "0", "false", "off", "no", "disable", "disabled":
			return 0, nil
		}
		return 0, fmt.Errorf("invalid bool %q", text)
	case cfr.KindEnum:
		if v, ok := o.EnumValue(t); ok {
			return v, nil
		}
		if v, err := parseUint(t); err == nil {
			return v, nil
		}
		names := make([]string, 0, len(o.EnumValues))
		for _, e := range o.EnumValues {
			names = append(names, e.UIName)
		}
		return 0, fmt.Errorf("invalid choice %q (one of: %s)", text, strings.Join(names, ", "))
	}
	return parseUint(t)
}

func parseUint(t string) (uint32, error) {
	v, err := strconv.ParseUint(t, 0, 32)
	if err != nil {
		return 0, errors.New("invalid number " + strconv.Quote(t))
	}
	return uint32(v), nil
}

func display(o *cfr.Option, v uint32) string {
	switch o.Kind {
	case cfr.KindBool:
		if v != 0 {
			return "Enabled"
		}
		return "Disabled"
	case cfr.KindEnum:
		if n, ok := o.EnumName(v); ok {
			return n
		}
		return fmt.Sprintf("%d (not a listed choice)", v)
	case cfr.KindNumber:
		if o.DisplayFlags&cfr.DisplayHex != 0 {
			return fmt.Sprintf("0x%x", v)
		}
	}
	return strconv.FormatUint(uint64(v), 10)
}

func flagNames(f uint32) []string {
	var out []string
	for _, n := range []struct {
		bit  uint32
		name string
	}{
		{cfr.FlagReadOnly, "readonly"}, {cfr.FlagInactive, "inactive"}, {cfr.FlagSuppress, "suppress"},
		{cfr.FlagVolatile, "volatile"}, {cfr.FlagRuntime, "runtime"}, {cfr.FlagLockAtBoot, "lock-at-boot"},
	} {
		if f&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}
