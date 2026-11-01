package provision

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/9elements/cbprov/pkg/image"
)

// Spec is a provisioning file. Map order is kept so changes apply as written.
//
//	vpd:     {serial_number: SN123}
//	rw_vpd:  {asset_tag: A1}
//	schema:  cfr.bin
//	options: {power_on_after_fail: Enable}
//	options_reset: [boot_delay]   # or "all"
//	payload: {fallback/payload: linux.elf}
type Spec struct {
	VPD          Ordered       `yaml:"vpd"`
	RWVPD        Ordered       `yaml:"rw_vpd"`
	Schema       string        `yaml:"schema"`
	Options      Ordered       `yaml:"options"`
	OptionsReset ResetList     `yaml:"options_reset"`
	Payload      Ordered       `yaml:"payload"`
	PayloadOpts  PayloadConfig `yaml:"payload_options"`
}

// PayloadConfig holds settings shared by all payload entries.
type PayloadConfig struct {
	Compression string `yaml:"compression"`
}

// Ordered is a YAML mapping of scalars that keeps document order.
type Ordered []KV

// UnmarshalYAML implements yaml.Unmarshaler.
func (o *Ordered) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: value of %s must be a scalar", v.Line, k.Value)
		}
		*o = append(*o, KV{Key: k.Value, Value: v.Value})
	}
	return nil
}

// ResetList is a list of option names or the scalar "all".
type ResetList struct {
	All   bool
	Names []string
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *ResetList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Value == "all" {
		r.All = true
		return nil
	}
	return n.Decode(&r.Names)
}

// LoadSpec reads a provisioning file.
func LoadSpec(path string) (*Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Spec
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Apply runs all changes of a spec. Relative paths resolve against baseDir.
// Order: VPD, schema, options, payload, so options validate against a schema
// embedded by the same file.
func Apply(im *image.Image, s *Spec, baseDir string, force bool) (Warnings, error) {
	var w Warnings
	path := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(baseDir, p)
	}
	if len(s.VPD) > 0 {
		ww, err := SetVPD(im, "RO_VPD", s.VPD)
		if err != nil {
			return w, fmt.Errorf("vpd: %w", err)
		}
		w = append(w, ww...)
	}
	if len(s.RWVPD) > 0 {
		ww, err := SetVPD(im, "RW_VPD", s.RWVPD)
		if err != nil {
			return w, fmt.Errorf("rw_vpd: %w", err)
		}
		w = append(w, ww...)
	}
	if s.Schema != "" {
		raw, err := os.ReadFile(path(s.Schema))
		if err != nil {
			return w, fmt.Errorf("schema: %w", err)
		}
		ww, err := EmbedSchema(im, raw)
		if err != nil {
			return w, fmt.Errorf("schema: %w", err)
		}
		w = append(w, ww...)
	}
	if len(s.Options) > 0 || s.OptionsReset.All || len(s.OptionsReset.Names) > 0 {
		set, _, err := OpenOptions(im, nil)
		if err != nil {
			return w, fmt.Errorf("options: %w", err)
		}
		if s.OptionsReset.All {
			if _, err := set.ResetAll(); err != nil {
				return w, fmt.Errorf("options_reset: %w", err)
			}
		}
		for _, n := range s.OptionsReset.Names {
			if _, err := set.Reset(n); err != nil {
				return w, fmt.Errorf("options_reset: %w", err)
			}
		}
		for _, kv := range s.Options {
			if err := set.SetValue(kv.Key, kv.Value); err != nil {
				return w, fmt.Errorf("options: %w", err)
			}
		}
		if set.Schema() == nil && len(s.Options) > 0 {
			w.add("no CFR schema in image: options written as raw numbers without validation")
		}
		if err := CommitOptions(im, set); err != nil {
			return w, err
		}
	}
	for _, kv := range s.Payload {
		data, err := os.ReadFile(path(kv.Value))
		if err != nil {
			return w, fmt.Errorf("payload: %w", err)
		}
		ww, err := ReplacePayload(im, PayloadSpec{Name: kv.Key, Data: data, Compression: s.PayloadOpts.Compression, Force: force})
		if err != nil {
			return w, fmt.Errorf("payload %s: %w", kv.Key, err)
		}
		w = append(w, ww...)
	}
	return w, nil
}
