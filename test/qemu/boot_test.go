package qemu

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBootFixtures boots the unprovisioned fixtures; it proves the harness,
// not cbprov. Needs CBPROV_FIXTURES (e.g. .cache/fixtures).
func TestBootFixtures(t *testing.T) {
	dir := os.Getenv("CBPROV_FIXTURES")
	if dir == "" {
		t.Skip("CBPROV_FIXTURES not set")
	}
	for _, tc := range []struct {
		name   string
		arch   Arch
		expect []string
		smbios bool
		cfr    bool
	}{
		{"q35", Q35, []string{"CBPROV-OPT cbprov_test_bool=0", "CBPROV-OPT cbprov_test_enum=1", "CBPROV-OPT cbprov_test_num=42"}, true, true},
		{"q35-cbfsverify", Q35, nil, true, true},
		{"q35-vboot", Q35, nil, true, false},
		{"i440fx", I440FX, nil, true, false},
		{"aarch64", AArch64, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rom := filepath.Join(dir, tc.name, "coreboot.rom")
			if _, err := os.Stat(rom); err != nil {
				t.Skipf("fixture not built: %v", err)
			}
			if !Available(tc.arch) {
				t.Skipf("%s not installed", Binary(tc.arch))
			}
			m, err := Boot(context.Background(), Options{
				ROM: rom, Arch: tc.arch, Timeout: 2 * time.Minute,
				ExpectSerial: append(tc.expect, "CBPROV-PAYLOAD-A"),
			})
			if m != nil {
				defer m.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(m.Serial(), "coreboot-") {
				t.Error("no coreboot banner on serial")
			}

			table, err := m.DumpCorebootTable()
			if err != nil {
				t.Fatal(err)
			}
			recs, err := ParseCorebootTable(table)
			if err != nil {
				t.Fatal(err)
			}
			hasCFR := false
			for _, r := range recs {
				hasCFR = hasCFR || r.Tag == TagCFR
			}
			if hasCFR != tc.cfr {
				t.Errorf("CFR record present = %v, want %v", hasCFR, tc.cfr)
			}
			t.Logf("coreboot table: %d bytes, %d records", len(table), len(recs))

			if tc.smbios {
				s, err := m.FindSMBIOS()
				if err != nil {
					t.Fatal(err)
				}
				sys, err := s.System()
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("SMBIOS %d.%d at 0x%x: %+v", s.Major, s.Minor, s.EntryAddr, sys)
				if sys.Manufacturer == "" || sys.ProductName == "" {
					t.Errorf("empty SMBIOS type 1 strings: %+v", sys)
				}
			}

			rom0, _ := os.ReadFile(rom)
			flash, err := m.Flash()
			if tc.arch == AArch64 {
				if err != ErrNoFlash {
					t.Errorf("Flash() = %v, want ErrNoFlash", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(flash) != len(rom0) {
				t.Errorf("flash size %d, want %d", len(flash), len(rom0))
			}
		})
	}
}
