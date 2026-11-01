package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/9elements/cbprov/pkg/cbfs"
	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/options"
	"github.com/9elements/cbprov/pkg/provision"
	"github.com/9elements/cbprov/pkg/vpd"
)

type showReport struct {
	Image        imageInfo          `json:"image"`
	Regions      []image.Region     `json:"regions"`
	Verification *cbfs.Verification `json:"verification,omitempty"`
	VPD          []vpdReport        `json:"vpd"`
	Options      *optionsReport     `json:"options,omitempty"`
	Payloads     []payloadInfo      `json:"payloads"`
	Errors       []string           `json:"errors,omitempty"`
}

type imageInfo struct {
	Path     string `json:"path"`
	Size     int    `json:"size"`
	Board    string `json:"board,omitempty"`
	Version  string `json:"coreboot_version,omitempty"`
	CBFSFree uint32 `json:"cbfs_free"`
}

type vpdReport struct {
	Region  string     `json:"region"`
	Entries []vpdEntry `json:"entries"`
}

type vpdEntry struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Set    bool   `json:"set"`
	SMBIOS string `json:"smbios,omitempty"`
	Note   string `json:"note,omitempty"`
}

type optionsReport struct {
	Schema  string          `json:"schema"`
	Erased  bool            `json:"erased"`
	Options []options.Value `json:"options"`
}

func showCmd() *cobra.Command {
	var asJSON bool
	var schemaPath string
	c := &cobra.Command{
		Use:   "show IMAGE",
		Short: "Print everything provisionable in an image",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			im, err := image.Open(args[0])
			if err != nil {
				return err
			}
			sch, err := readOptional(schemaPath)
			if err != nil {
				return err
			}
			r := buildReport(args[0], im, sch)
			if asJSON {
				return printJSON(r)
			}
			printReport(r)
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	c.Flags().StringVar(&schemaPath, "schema", "", "CFR schema `FILE` instead of CBFS cfr.bin")
	return c
}

// buildReport collects what it can; a broken section is reported, not fatal.
func buildReport(path string, im *image.Image, schema []byte) showReport {
	r := showReport{Image: imageInfo{Path: path, Size: len(im.Data)}, Regions: im.Regions()}
	fail := func(what string, err error) { r.Errors = append(r.Errors, fmt.Sprintf("%s: %v", what, err)) }

	cfg := provision.BuildConfig(im)
	r.Image.Board = strings.TrimSpace(cfg.String("MAINBOARD_VENDOR") + " " + cfg.String("MAINBOARD_PART_NUMBER"))
	if fs, err := cbfs.Open(im, provision.ROCBFS); err != nil {
		fail("CBFS", err)
	} else {
		r.Image.Version = corebootVersion(fs)
		if free, err := fs.Free(); err == nil {
			r.Image.CBFSFree = free
		}
	}
	if v, err := cbfs.DetectVerification(im); err != nil {
		fail("verification", err)
	} else {
		r.Verification = &v
	}

	for _, region := range []string{"RO_VPD", "RW_VPD"} {
		if !im.HasRegion(region) {
			continue
		}
		st, _, err := provision.OpenVPD(im, region)
		if err != nil {
			fail(region, err)
			continue
		}
		r.VPD = append(r.VPD, vpdSection(region, st, cfg.Bool))
	}

	if im.HasRegion(options.Region) {
		set, src, err := provision.OpenOptions(im, schema)
		if err != nil {
			fail("options", err)
		} else if vals, err := set.List(); err != nil {
			fail("options", err)
		} else {
			r.Options = &optionsReport{Schema: src, Erased: set.Erased(), Options: vals}
		}
	}

	ps, err := payloads(im)
	if err != nil {
		fail("payloads", err)
	}
	r.Payloads = ps
	return r
}

func vpdSection(region string, st *vpd.Store, enabled func(string) bool) vpdReport {
	rep := vpdReport{Region: region}
	known := map[string]bool{}
	if region == "RO_VPD" {
		for _, k := range vpd.Keys() {
			known[k.Name] = true
			e := vpdEntry{Key: k.Name, SMBIOS: k.SMBIOS}
			if v, ok := st.Get(k.Name); ok {
				e.Value, e.Set = vpd.FormatValue(k.Name, v), true
			}
			switch {
			case k.Proposed:
				e.Note = "needs coreboot patch"
			case !enabled(k.Kconfig):
				e.Note = "CONFIG_" + k.Kconfig + " off"
			}
			if !e.Set && k.Proposed {
				continue // keep the listing short: unset proposed keys are noise
			}
			rep.Entries = append(rep.Entries, e)
		}
	}
	for _, en := range st.Entries {
		if known[en.Key] {
			continue
		}
		rep.Entries = append(rep.Entries, vpdEntry{Key: en.Key, Value: vpd.FormatValue(en.Key, en.Value), Set: true})
	}
	return rep
}

// corebootVersion reads COREBOOT_VERSION from CBFS build_info ("KEY: value")
// or revision ("#define KEY value"); builds without git tags leave it empty,
// then the git revision is used.
func corebootVersion(fs *cbfs.FS) string {
	vals := map[string]string{}
	for _, name := range []string{"build_info", "revision"} {
		b, err := fs.Extract(name)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimPrefix(strings.TrimSpace(sc.Text()), "#define ")
			k, v, ok := strings.Cut(line, ":")
			if !ok || strings.ContainsAny(k, " \t") {
				k, v, ok = strings.Cut(line, " ")
			}
			if ok && vals[k] == "" {
				vals[k] = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	if v := vals["COREBOOT_VERSION"]; v != "" {
		return v
	}
	if r := vals["COREBOOT_ORIGIN_GIT_REVISION"]; r != "" {
		return "git " + r
	}
	return ""
}

func printReport(r showReport) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintf(tw, "Image\t%s  %s", r.Image.Path, size(uint64(r.Image.Size)))
	if r.Image.Board != "" {
		fmt.Fprintf(tw, "  board: %s", r.Image.Board)
	}
	if r.Image.Version != "" {
		fmt.Fprintf(tw, "  coreboot %s", r.Image.Version)
	}
	fmt.Fprintln(tw)
	var rs []string
	for _, rg := range r.Regions {
		switch rg.Name {
		case "RO_VPD", "RW_VPD", "SMMSTORE", "COREBOOT", "FW_MAIN_A", "FW_MAIN_B":
			s := rg.Name + " " + size(uint64(rg.Size))
			if rg.Name == "COREBOOT" {
				s += " (" + size(uint64(r.Image.CBFSFree)) + " free)"
			}
			rs = append(rs, s)
		}
	}
	fmt.Fprintf(tw, "Regions\t%s\n", strings.Join(rs, "  "))
	if v := r.Verification; v != nil {
		fmt.Fprintf(tw, "Signed\tCBFS verification: %s  vboot: %s\n", onOff(v.MetadataHash), onOff(v.Vboot))
	}
	for _, sec := range r.VPD {
		fmt.Fprintf(tw, "\nVPD (%s)\t\t\t\n", sec.Region)
		if len(sec.Entries) == 0 {
			fmt.Fprintln(tw, "  (empty)\t\t\t")
		}
		for _, e := range sec.Entries {
			val := e.Value
			if !e.Set {
				val = "(unset)"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", e.Key, val, e.SMBIOS, e.Note)
		}
	}
	if o := r.Options; o != nil {
		src := o.Schema
		if src == "" {
			src = "none, raw mode"
		}
		fmt.Fprintf(tw, "\nOptions (SMMSTORE, schema: %s)\t\t\t\n", src)
		if o.Erased {
			fmt.Fprintln(tw, "  store erased: coreboot uses defaults\t\t\t")
		}
		if len(o.Options) > 0 {
			fmt.Fprintln(tw, "  NAME\tVALUE\tDEFAULT\tSTATE")
		}
		for _, v := range o.Options {
			def := v.DefaultStr
			if def == "" {
				def = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", v.Name, v.Display, def, v.State)
		}
	}
	fmt.Fprintln(tw, "\nPayloads\t\t\t")
	for _, p := range r.Payloads {
		fmt.Fprintf(tw, "  %s\t%s %s\t%s\t%s\n", p.Name, p.Region, p.Type, size(uint64(p.Size)), p.Compression)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(tw, "\nerror\t%s\n", e)
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func size(n uint64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}
