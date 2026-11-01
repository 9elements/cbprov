package buildconfig

import "testing"

func TestParse(t *testing.T) {
	c := Parse([]byte(`#
# Automatically generated file; DO NOT EDIT.
CONFIG_VPD=y
# CONFIG_CBFS_VERIFICATION is not set
CONFIG_SMMSTORE_BLOCK_SIZE=65536
CONFIG_VPD_FMAP_SIZE=0x4000
CONFIG_MAINBOARD_PART_NUMBER="QEMU x86 q35/ich9"
`))
	if !c.Bool("VPD") || c.Bool("CBFS_VERIFICATION") {
		t.Errorf("bools wrong: %v", c)
	}
	if got := c.Int("SMMSTORE_BLOCK_SIZE", 0); got != 65536 {
		t.Errorf("SMMSTORE_BLOCK_SIZE = %d", got)
	}
	if got := c.Int("VPD_FMAP_SIZE", 0); got != 0x4000 {
		t.Errorf("VPD_FMAP_SIZE = %#x", got)
	}
	if got := c.Int("MISSING", 7); got != 7 {
		t.Errorf("default = %d", got)
	}
	if got := c.String("MAINBOARD_PART_NUMBER"); got != "QEMU x86 q35/ich9" {
		t.Errorf("part number = %q", got)
	}
}
