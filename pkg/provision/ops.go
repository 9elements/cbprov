// Package provision implements the image changes behind the CLI commands and
// applies provisioning files that combine them.
package provision

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"

	"github.com/9elements/cbprov/pkg/buildconfig"
	"github.com/9elements/cbprov/pkg/cbfs"
	"github.com/9elements/cbprov/pkg/cfr"
	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/options"
	"github.com/9elements/cbprov/pkg/vpd"
)

// ROCBFS is the FMAP region of the read-only CBFS.
const ROCBFS = "COREBOOT"

// CBFSRegions are the FMAP regions a CBFS change may touch: the RO CBFS, its
// copy COREBOOT_B (Intel Top Swap, AMD PSP A/B recovery) and the BOOTBLOCK
// regions holding their metadata hash anchors.
var CBFSRegions = []string{ROCBFS, "COREBOOT_B", "BOOTBLOCK", "BOOTBLOCK_B"}

// KV is an ordered key/value pair from the command line or a provisioning file.
type KV struct {
	Key   string
	Value string
}

// Warnings collects non-fatal findings to show the user.
type Warnings []string

func (w *Warnings) add(format string, args ...any) { *w = append(*w, fmt.Sprintf(format, args...)) }

// BuildConfig returns the Kconfig stored in the RO CBFS, or an empty config.
func BuildConfig(im *image.Image) buildconfig.Config {
	fs, err := cbfs.Open(im, ROCBFS)
	if err != nil {
		return buildconfig.Config{}
	}
	b, err := fs.Extract(buildconfig.FileName)
	if err != nil {
		return buildconfig.Config{}
	}
	return buildconfig.Parse(b)
}

// LoadSchema returns the CFR schema: from override (raw CFR record or a
// coreboot table dump) if given, else from CBFS. A nil schema means raw mode.
func LoadSchema(im *image.Image, override []byte) (*cfr.Schema, string, error) {
	if override != nil {
		s, err := ParseSchemaBlob(override)
		return s, "file", err
	}
	fs, err := cbfs.Open(im, ROCBFS)
	if err != nil {
		return nil, "", nil
	}
	b, err := fs.Extract(cfr.FileName)
	if err != nil {
		return nil, "", nil
	}
	s, err := cfr.Parse(b)
	if err != nil {
		return nil, "", fmt.Errorf("CBFS %s: %w", cfr.FileName, err)
	}
	return s, "cbfs:" + cfr.FileName, nil
}

// ParseSchemaBlob accepts a raw LB_TAG_CFR record or a coreboot table dump.
func ParseSchemaBlob(b []byte) (*cfr.Schema, error) {
	if bytes.HasPrefix(b, []byte("LBIO")) {
		s, _, err := cfr.FromCorebootTable(b)
		return s, err
	}
	return cfr.Parse(b)
}

// OpenOptions loads the option view of the image.
func OpenOptions(im *image.Image, schemaOverride []byte) (*options.Set, string, error) {
	region, err := im.RegionData(options.Region)
	if err != nil {
		return nil, "", fmt.Errorf("image has no %s region; options need CONFIG_SMMSTORE", options.Region)
	}
	schema, src, err := LoadSchema(im, schemaOverride)
	if err != nil {
		return nil, "", err
	}
	bs := BuildConfig(im).Int("SMMSTORE_BLOCK_SIZE", options.DefaultBlockSize)
	set, err := options.Load(region, bs, schema)
	return set, src, err
}

// CommitOptions writes the option changes back into the image.
func CommitOptions(im *image.Image, set *options.Set) error {
	region, err := im.RegionData(options.Region)
	if err != nil {
		return err
	}
	b := set.Bytes()
	if len(b) != len(region) {
		return fmt.Errorf("%s: store size %d != region size %d", options.Region, len(b), len(region))
	}
	copy(region, b)
	return nil
}

// OpenVPD decodes a VPD region.
func OpenVPD(im *image.Image, region string) (*vpd.Store, []byte, error) {
	data, err := im.RegionData(region)
	if err != nil {
		return nil, nil, fmt.Errorf("image has no %s region; VPD needs CONFIG_VPD", region)
	}
	st, err := vpd.Decode(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", region, err)
	}
	return st, data, nil
}

// SetVPD sets keys in a VPD region.
func SetVPD(im *image.Image, region string, kvs []KV) (Warnings, error) {
	var w Warnings
	st, data, err := OpenVPD(im, region)
	if err != nil {
		return nil, err
	}
	cfg := BuildConfig(im)
	for _, kv := range kvs {
		val, err := vpd.ParseValue(kv.Key, kv.Value)
		if err != nil {
			return nil, err
		}
		if err := st.Set(kv.Key, val); err != nil {
			return nil, err
		}
		w = append(w, vpdKeyWarnings(cfg, region, kv.Key)...)
	}
	return w, writeVPD(st, data)
}

// DeleteVPD removes keys from a VPD region; missing keys are an error.
func DeleteVPD(im *image.Image, region string, keys []string) error {
	st, data, err := OpenVPD(im, region)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if !st.Delete(k) {
			return fmt.Errorf("%s: key %s not set", region, k)
		}
	}
	return writeVPD(st, data)
}

func writeVPD(st *vpd.Store, data []byte) error {
	b, err := st.Encode()
	if err != nil {
		return err
	}
	copy(data, b)
	return nil
}

func vpdKeyWarnings(cfg buildconfig.Config, region, key string) []string {
	k, ok := vpd.LookupKey(key)
	if !ok {
		return []string{fmt.Sprintf("VPD key %s is not one coreboot maps to SMBIOS", key)}
	}
	var w []string
	if k.Proposed {
		w = append(w, fmt.Sprintf("VPD key %s needs a coreboot patch; current coreboot ignores it", key))
	}
	if region != "RO_VPD" {
		w = append(w, fmt.Sprintf("coreboot reads %s from RO_VPD only", key))
	}
	if len(cfg) > 0 && k.Kconfig != "" && !cfg.Bool(k.Kconfig) {
		w = append(w, fmt.Sprintf("VPD key %s is ignored: CONFIG_%s is not set in this image", key, k.Kconfig))
	}
	return w
}

// PayloadSpec describes a payload replacement.
type PayloadSpec struct {
	Name        string // CBFS name, default fallback/payload
	Data        []byte
	Compression string // "", "none", "lzma", "lz4"; "" keeps the old file's compression
	Flat        bool
	LoadAddr    uint64
	Entry       uint64
	Force       bool
}

// ErrSigned is returned when a change would break a signature cbprov cannot renew.
var ErrSigned = errors.New("image is signed")

// ReplacePayload swaps a payload in the RO CBFS and its COREBOOT_B copy.
func ReplacePayload(im *image.Image, p PayloadSpec) (Warnings, error) {
	var w Warnings
	if p.Name == "" {
		p.Name = "fallback/payload"
	}
	ver, err := cbfs.DetectVerification(im)
	if err != nil {
		return nil, err
	}
	if ver.Vboot && !p.Force {
		return nil, fmt.Errorf("%w: vboot RW slots (FW_MAIN_A/B) present; payload changes need re-signing, which cbprov does not do yet (--force changes the RO CBFS only)", ErrSigned)
	}
	// Only the ELF magic is checked: cbfstool accepts ELFs with broken section
	// headers and so does the SELF converter, which reads program headers only.
	if !p.Flat && !bytes.HasPrefix(p.Data, []byte(elf.ELFMAG)) {
		return nil, errors.New("payload is not an ELF file (use --flat with --load and --entry for raw binaries)")
	}
	// coreboot adds the payload to every RO CBFS (CBFS_REGIONS).
	regions := []string{ROCBFS}
	if im.HasRegion("COREBOOT_B") {
		regions = append(regions, "COREBOOT_B")
	}
	for _, region := range regions {
		if err := replacePayloadIn(im, region, p, &w); err != nil {
			return nil, err
		}
	}
	if ver.MetadataHash {
		if err := cbfs.UpdateMetadataHash(im); err != nil {
			return nil, err
		}
		w.add("CBFS metadata hash in the bootblock updated; if the bootblock is verified by Boot Guard or the AMD PSP, re-sign the image")
	}
	if ver.Vboot {
		w.add("only the RO CBFS was changed; vboot RW slots still boot the old payload")
	}
	return w, nil
}

func replacePayloadIn(im *image.Image, region string, p PayloadSpec, w *Warnings) error {
	fs, err := cbfs.Open(im, region)
	if err != nil {
		return err
	}
	comp := cbfs.CompressLZMA
	old, found, err := findFile(fs, p.Name)
	if err != nil {
		return err
	}
	if found {
		comp = PayloadCompression(old)
	} else {
		w.add("%s did not exist in %s; adding it", p.Name, region)
	}
	if p.Compression != "" {
		if comp, err = ParseCompression(p.Compression); err != nil {
			return err
		}
	}
	if found {
		if err := fs.Remove(p.Name); err != nil {
			return err
		}
	}
	if p.Flat {
		return fs.AddPayloadFlat(p.Name, p.Data, p.LoadAddr, p.Entry, comp)
	}
	return fs.AddPayloadELF(p.Name, p.Data, comp)
}

// EmbedSchema stores a CFR schema in the RO CBFS so later commands find it.
func EmbedSchema(im *image.Image, raw []byte) (Warnings, error) {
	var w Warnings
	if _, err := cfr.Parse(raw); err != nil {
		return nil, fmt.Errorf("not a valid CFR record: %w", err)
	}
	ver, err := cbfs.DetectVerification(im)
	if err != nil {
		return nil, err
	}
	fs, err := cbfs.Open(im, ROCBFS)
	if err != nil {
		return nil, err
	}
	if _, found, err := findFile(fs, cfr.FileName); err != nil {
		return nil, err
	} else if found {
		if err := fs.Remove(cfr.FileName); err != nil {
			return nil, err
		}
	}
	if err := fs.AddRaw(cfr.FileName, raw, cbfs.CompressLZMA); err != nil {
		return nil, err
	}
	if ver.MetadataHash {
		if err := cbfs.UpdateMetadataHash(im); err != nil {
			return nil, err
		}
		w.add("CBFS metadata hash in the bootblock updated")
	}
	return w, nil
}

// ParseCompression maps a CLI name to a CBFS compression.
func ParseCompression(s string) (cbfs.Compression, error) {
	switch s {
	case "none":
		return cbfs.CompressNone, nil
	case "lzma":
		return cbfs.CompressLZMA, nil
	case "lz4":
		return cbfs.CompressLZ4, nil
	}
	return 0, fmt.Errorf("unknown compression %q (none, lzma, lz4)", s)
}

// PayloadCompression returns the compression of a SELF payload's first
// compressed segment; SELF files themselves carry no compression attribute.
func PayloadCompression(f cbfs.File) cbfs.Compression {
	for _, s := range f.Segments {
		if s.Compression != cbfs.CompressNone {
			return s.Compression
		}
	}
	if len(f.Segments) > 0 {
		return cbfs.CompressNone
	}
	return f.Compression
}

func findFile(fs *cbfs.FS, name string) (cbfs.File, bool, error) {
	files, err := fs.Files()
	if err != nil {
		return cbfs.File{}, false, err
	}
	for _, f := range files {
		if f.Name == name {
			return f, true, nil
		}
	}
	return cbfs.File{}, false, nil
}
