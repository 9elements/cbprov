package main

import (
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/options"
	"github.com/9elements/cbprov/pkg/provision"
)

func applyCmd() *cobra.Command {
	var out output
	var file string
	var force bool
	c := &cobra.Command{
		Use:   "apply IMAGE -f PROVISION.yaml",
		Short: "Apply a provisioning file (VPD, schema, options, payloads)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if file == "" {
				return errors.New("-f is required")
			}
			spec, err := provision.LoadSpec(file)
			if err != nil {
				return err
			}
			allowed := []string{"RO_VPD", "RW_VPD", options.Region, provision.ROCBFS}
			return out.edit(args[0], allowed, func(im *image.Image) (provision.Warnings, error) {
				return provision.Apply(im, spec, filepath.Dir(file), force)
			})
		},
	}
	c.Flags().StringVarP(&file, "file", "f", "", "provisioning `FILE` (YAML)")
	c.Flags().BoolVar(&force, "force", false, "as payload replace --force")
	out.register(c)
	return c
}
