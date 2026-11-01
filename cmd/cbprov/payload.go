package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/9elements/cbprov/pkg/cbfs"
	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/provision"
)

// CBFS payload file types (cbfs_serialized.h).
const (
	typeSELF       = 0x20
	typeFITPayload = 0x21
)

func payloadCmd() *cobra.Command {
	c := &cobra.Command{Use: "payload", Short: "List and replace payloads in CBFS"}

	var listJSON bool
	list := &cobra.Command{
		Use:   "list IMAGE",
		Short: "List payloads in all CBFS regions",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			im, err := image.Open(args[0])
			if err != nil {
				return err
			}
			ps, err := payloads(im)
			if err != nil {
				return err
			}
			if listJSON {
				return printJSON(ps)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "REGION\tNAME\tTYPE\tSIZE\tCOMPRESSION")
			for _, p := range ps {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", p.Region, p.Name, p.Type, p.Size, p.Compression)
			}
			return tw.Flush()
		},
	}
	list.Flags().BoolVar(&listJSON, "json", false, "JSON output")

	var out output
	var spec provision.PayloadSpec
	var file string
	replace := &cobra.Command{
		Use:   "replace IMAGE --file PAYLOAD",
		Short: "Replace a payload (ELF, or flat binary with --flat)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			if spec.Flat && (!cmd.Flags().Changed("load") || !cmd.Flags().Changed("entry")) {
				return fmt.Errorf("--flat needs --load and --entry")
			}
			data, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			spec.Data = data
			return out.edit(args[0], []string{provision.ROCBFS}, func(im *image.Image) (provision.Warnings, error) {
				return provision.ReplacePayload(im, spec)
			})
		},
	}
	replace.Flags().StringVar(&file, "file", "", "new payload `FILE`")
	replace.Flags().StringVar(&spec.Name, "name", "fallback/payload", "CBFS `NAME` of the payload")
	replace.Flags().StringVar(&spec.Compression, "compression", "", "none, lzma or lz4 (default: keep the old file's)")
	replace.Flags().BoolVar(&spec.Flat, "flat", false, "FILE is a flat binary")
	replace.Flags().Uint64Var(&spec.LoadAddr, "load", 0, "load `ADDR` for --flat")
	replace.Flags().Uint64Var(&spec.Entry, "entry", 0, "entry `ADDR` for --flat")
	replace.Flags().BoolVar(&spec.Force, "force", false, "change the RO CBFS even if the image has vboot RW slots")
	out.register(replace)

	c.AddCommand(list, replace)
	return c
}

type payloadInfo struct {
	Region      string `json:"region"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Size        uint32 `json:"size"`
	Compression string `json:"compression"`
}

func payloads(im *image.Image) ([]payloadInfo, error) {
	var out []payloadInfo
	for _, region := range []string{provision.ROCBFS, "FW_MAIN_A", "FW_MAIN_B"} {
		if !im.HasRegion(region) {
			continue
		}
		fs, err := cbfs.Open(im, region)
		if err != nil {
			if region == provision.ROCBFS {
				return nil, err
			}
			continue // vboot slots may be unsigned/empty
		}
		files, err := fs.Files()
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.Type != typeSELF && f.Type != typeFITPayload {
				continue
			}
			out = append(out, payloadInfo{Region: region, Name: f.Name, Type: f.TypeName, Size: f.Size, Compression: provision.PayloadCompression(f).String()})
		}
	}
	return out, nil
}
