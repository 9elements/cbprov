package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/9elements/cbprov/pkg/cfr"
	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/provision"
)

func schemaCmd() *cobra.Command {
	c := &cobra.Command{Use: "schema", Short: "Extract, embed and show CFR option schemas"}

	var from, out string
	extract := &cobra.Command{
		Use:   "extract --from-cbtable DUMP -o CFR.BIN",
		Short: "Extract the CFR record from a coreboot table dump",
		Long: "Extract the raw CFR record from a coreboot table dump (starting at the LBIO header),\n" +
			"e.g. captured on a running board. The result can be embedded with 'schema embed'.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if from == "" || out == "" {
				return errors.New("--from-cbtable and -o are required")
			}
			b, err := os.ReadFile(from)
			if err != nil {
				return err
			}
			if off, err := cfr.FindCorebootTable(b, 0); err == nil && off > 0 {
				b = b[off:]
			}
			_, raw, err := cfr.FromCorebootTable(b)
			if err != nil {
				var fwd cfr.ForwardError
				if errors.As(err, &fwd) {
					return fmt.Errorf("%w; dump memory at 0x%x instead", err, fwd.Addr)
				}
				return err
			}
			return os.WriteFile(out, raw, 0o644)
		},
	}
	extract.Flags().StringVar(&from, "from-cbtable", "", "coreboot table dump `FILE`")
	extract.Flags().StringVarP(&out, "output", "o", "", "output `FILE`")

	var embedOut output
	embed := &cobra.Command{
		Use:   "embed IMAGE CFR.BIN",
		Short: "Store a CFR schema in the image's CBFS as cfr.bin",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			return embedOut.edit(args[0], []string{provision.ROCBFS}, func(im *image.Image) (provision.Warnings, error) {
				return provision.EmbedSchema(im, raw)
			})
		},
	}
	embedOut.register(embed)

	var showJSON bool
	show := &cobra.Command{
		Use:   "show IMAGE|CFR.BIN",
		Short: "Print a schema from an image or a CFR file",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			b, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var s *cfr.Schema
			if im, err := image.Parse(b); err == nil {
				var src string
				if s, src, err = provision.LoadSchema(im, nil); err != nil {
					return err
				}
				if src == "" {
					return errors.New("image has no CBFS cfr.bin")
				}
			} else if s, err = provision.ParseSchemaBlob(b); err != nil {
				return err
			}
			if showJSON {
				return printJSON(s)
			}
			var buf bytes.Buffer
			for _, f := range s.Forms {
				printSchema(&buf, f, 0)
			}
			_, err = os.Stdout.Write(buf.Bytes())
			return err
		},
	}
	show.Flags().BoolVar(&showJSON, "json", false, "JSON output")

	c.AddCommand(extract, embed, show)
	return c
}

func printSchema(w *bytes.Buffer, o *cfr.Option, depth int) {
	ind := strings.Repeat("  ", depth)
	switch o.Kind {
	case cfr.KindForm:
		fmt.Fprintf(w, "%s[%s]\n", ind, o.UIName)
		for _, c := range o.Options {
			printSchema(w, c, depth+1)
		}
		return
	case cfr.KindComment:
		fmt.Fprintf(w, "%s# %s\n", ind, o.UIName)
		return
	}
	fmt.Fprintf(w, "%s%s (%s) %q", ind, o.Name, o.Kind, o.UIName)
	switch o.Kind {
	case cfr.KindEnum:
		var cs []string
		for _, e := range o.EnumValues {
			cs = append(cs, fmt.Sprintf("%d=%s", e.Value, e.UIName))
		}
		fmt.Fprintf(w, " default=%d choices=[%s]", o.Default, strings.Join(cs, ", "))
	case cfr.KindNumber:
		fmt.Fprintf(w, " default=%d range=[%d..%d] step=%d", o.Default, o.Min, o.Max, o.Step)
	case cfr.KindBool:
		fmt.Fprintf(w, " default=%d", o.Default)
	case cfr.KindVarchar:
		fmt.Fprintf(w, " default=%q", o.DefaultStr)
	}
	w.WriteString("\n")
}
