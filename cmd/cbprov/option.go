package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/options"
	"github.com/9elements/cbprov/pkg/provision"
)

func optionCmd() *cobra.Command {
	c := &cobra.Command{Use: "option", Short: "Read and change CFR options stored in SMMSTORE"}
	var schemaPath string
	c.PersistentFlags().StringVar(&schemaPath, "schema", "", "CFR schema `FILE` (raw CFR record or coreboot table dump) instead of CBFS cfr.bin")

	open := func(path string) (*image.Image, *options.Set, string, error) {
		im, err := image.Open(path)
		if err != nil {
			return nil, nil, "", err
		}
		sch, err := readOptional(schemaPath)
		if err != nil {
			return nil, nil, "", err
		}
		set, src, err := provision.OpenOptions(im, sch)
		return im, set, src, err
	}

	var listJSON bool
	list := &cobra.Command{
		Use:   "list IMAGE",
		Short: "List options with current value and default",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			_, set, src, err := open(args[0])
			if err != nil {
				return err
			}
			vals, err := set.List()
			if err != nil {
				return err
			}
			if listJSON {
				return printJSON(map[string]any{"schema": src, "erased": set.Erased(), "options": vals})
			}
			printOptions(src, set.Erased(), vals)
			return nil
		},
	}
	list.Flags().BoolVar(&listJSON, "json", false, "JSON output")

	var getJSON bool
	get := &cobra.Command{
		Use:   "get IMAGE NAME",
		Short: "Print one option",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			_, set, _, err := open(args[0])
			if err != nil {
				return err
			}
			v, err := set.Get(args[1])
			if err != nil {
				return err
			}
			if getJSON {
				return printJSON(v)
			}
			fmt.Println(v.Display)
			return nil
		},
	}
	get.Flags().BoolVar(&getJSON, "json", false, "JSON output")

	var setOut output
	var raw bool
	set := &cobra.Command{
		Use:   "set IMAGE NAME=VALUE...",
		Short: "Set options; VALUE is a choice name or a number",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			kvs, err := parseKVs(args[1:])
			if err != nil {
				return err
			}
			sch, err := readOptional(schemaPath)
			if err != nil {
				return err
			}
			return setOut.edit(args[0], []string{options.Region}, func(im *image.Image) (provision.Warnings, error) {
				var w provision.Warnings
				s, _, err := provision.OpenOptions(im, sch)
				if err != nil {
					return nil, err
				}
				if s.Schema() == nil {
					w = append(w, "no CFR schema (embed one with 'cbprov schema embed' or pass --schema): values are written without validation")
				}
				for _, kv := range kvs {
					if raw {
						v, err := parseRaw(kv.Value)
						if err != nil {
							return w, fmt.Errorf("option %s: %w", kv.Key, err)
						}
						err = s.SetRaw(kv.Key, v)
						if err != nil {
							return w, err
						}
						continue
					}
					if err := s.SetValue(kv.Key, kv.Value); err != nil {
						return w, err
					}
				}
				return w, provision.CommitOptions(im, s)
			})
		},
	}
	set.Flags().BoolVar(&raw, "raw", false, "write numeric values without schema checks")
	setOut.register(set)

	var resetOut output
	var all bool
	reset := &cobra.Command{
		Use:   "reset IMAGE [NAME...]",
		Short: "Delete stored values so coreboot uses its defaults",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if all == (len(args) > 1) {
				return errors.New("give option names or --all")
			}
			return resetOut.edit(args[0], []string{options.Region}, func(im *image.Image) (provision.Warnings, error) {
				s, _, err := provision.OpenOptions(im, nil)
				if err != nil {
					return nil, err
				}
				var w provision.Warnings
				if all {
					if _, err := s.ResetAll(); err != nil {
						return nil, err
					}
				}
				for _, n := range args[1:] {
					found, err := s.Reset(n)
					if err != nil {
						return nil, err
					}
					if !found {
						w = append(w, fmt.Sprintf("option %s was not stored", n))
					}
				}
				return w, provision.CommitOptions(im, s)
			})
		},
	}
	reset.Flags().BoolVar(&all, "all", false, "reset every coreboot option")
	resetOut.register(reset)

	c.AddCommand(list, get, set, reset)
	return c
}

func parseRaw(s string) (uint32, error) {
	var v uint32
	_, err := fmt.Sscan(s, &v)
	if err != nil || strings.HasPrefix(s, "0x") {
		var u uint64
		if _, err := fmt.Sscanf(s, "0x%x", &u); err != nil || u > 0xffffffff {
			return 0, fmt.Errorf("invalid number %q", s)
		}
		return uint32(u), nil
	}
	return v, nil
}

func printOptions(src string, erased bool, vals []options.Value) {
	switch {
	case src == "":
		fmt.Println("Schema: none (raw mode; embed one with 'cbprov schema embed')")
	default:
		fmt.Println("Schema:", src)
	}
	if erased {
		fmt.Println("Store:  erased (coreboot uses defaults; first write initialises it)")
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVALUE\tDEFAULT\tSTATE\tCHOICES")
	for _, v := range vals {
		def := v.DefaultStr
		if v.Default == nil && def == "" {
			def = "-"
		}
		state := string(v.State)
		if len(v.Flags) > 0 {
			state += " (" + strings.Join(v.Flags, ",") + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", v.Name, v.Display, def, state, strings.Join(v.Choices, "|"))
	}
	tw.Flush()
}
