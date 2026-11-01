package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/provision"
	"github.com/9elements/cbprov/pkg/vpd"
)

func vpdCmd() *cobra.Command {
	c := &cobra.Command{Use: "vpd", Short: "Read and write VPD key/value data (RO_VPD, RW_VPD)"}
	var region string
	c.PersistentFlags().StringVar(&region, "region", "RO_VPD", "FMAP `REGION` holding the VPD")

	var asJSON bool
	get := &cobra.Command{
		Use:   "get IMAGE [KEY...]",
		Short: "Print VPD keys",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			im, err := image.Open(args[0])
			if err != nil {
				return err
			}
			st, _, err := provision.OpenVPD(im, region)
			if err != nil {
				return err
			}
			entries := st.Entries
			if len(args) > 1 {
				entries = nil
				for _, k := range args[1:] {
					v, ok := st.Get(k)
					if !ok {
						return fmt.Errorf("%s: key %s not set", region, k)
					}
					entries = append(entries, vpd.Entry{Key: k, Value: v})
				}
			}
			if asJSON {
				m := make([]map[string]string, 0, len(entries))
				for _, e := range entries {
					m = append(m, map[string]string{"key": e.Key, "value": vpd.FormatValue(e.Key, e.Value)})
				}
				return printJSON(m)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			for _, e := range entries {
				fmt.Fprintf(tw, "%s\t%s\n", e.Key, vpd.FormatValue(e.Key, e.Value))
			}
			return tw.Flush()
		},
	}
	get.Flags().BoolVar(&asJSON, "json", false, "JSON output")

	var setOut output
	set := &cobra.Command{
		Use:   "set IMAGE KEY=VALUE...",
		Short: "Set VPD keys",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			kvs, err := parseKVs(args[1:])
			if err != nil {
				return err
			}
			return setOut.edit(args[0], []string{region}, func(im *image.Image) (provision.Warnings, error) {
				return provision.SetVPD(im, region, kvs)
			})
		},
	}
	setOut.register(set)

	var rmOut output
	rm := &cobra.Command{
		Use:   "rm IMAGE KEY...",
		Short: "Delete VPD keys",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return rmOut.edit(args[0], []string{region}, func(im *image.Image) (provision.Warnings, error) {
				return nil, provision.DeleteVPD(im, region, args[1:])
			})
		},
	}
	rmOut.register(rm)

	keys := &cobra.Command{
		Use:   "keys",
		Short: "List the VPD keys coreboot maps to SMBIOS",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY\tSMBIOS\tKCONFIG\tSTATUS")
			for _, k := range vpd.Keys() {
				st := "supported"
				if k.Proposed {
					st = "needs coreboot patch"
				}
				fmt.Fprintf(tw, "%s\t%s\tCONFIG_%s\t%s\n", k.Name, k.SMBIOS, k.Kconfig, st)
			}
			return tw.Flush()
		},
	}
	c.AddCommand(get, set, rm, keys)
	return c
}
