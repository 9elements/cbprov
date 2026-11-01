// Command cbprov inspects and provisions coreboot images offline.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/9elements/cbprov/pkg/image"
	"github.com/9elements/cbprov/pkg/provision"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:           "cbprov",
		Short:         "Inspect and provision coreboot images: VPD, CFR options, payloads",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(showCmd(), vpdCmd(), optionCmd(), schemaCmd(), payloadCmd(), applyCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// output holds the flags every writing command shares.
type output struct {
	path    string
	inPlace bool
}

func (o *output) register(c *cobra.Command) {
	c.Flags().StringVarP(&o.path, "output", "o", "", "write the result to `FILE`")
	c.Flags().BoolVar(&o.inPlace, "in-place", false, "overwrite the input image")
}

func (o *output) check() error {
	if (o.path == "") == !o.inPlace {
		return errors.New("give exactly one of -o FILE or --in-place")
	}
	return nil
}

// edit opens an image, runs fn and writes the result. Bytes outside the
// allowed FMAP regions must stay unchanged; this guards against a bug in any
// format package corrupting unrelated data.
func (o *output) edit(in string, allowed []string, fn func(im *image.Image) (provision.Warnings, error)) error {
	if err := o.check(); err != nil {
		return err
	}
	im, err := image.Open(in)
	if err != nil {
		return err
	}
	orig := bytes.Clone(im.Data)
	w, err := fn(im)
	printWarnings(w)
	if err != nil {
		return err
	}
	if err := checkChanges(im, orig, allowed); err != nil {
		return err
	}
	if _, err := image.Parse(im.Data); err != nil {
		return fmt.Errorf("result does not parse, not written: %w", err)
	}
	dst := o.path
	if o.inPlace {
		dst = in
	}
	if bytes.Equal(orig, im.Data) {
		fmt.Fprintln(os.Stderr, "no change")
		if !o.inPlace {
			return im.WriteFile(dst)
		}
		return nil
	}
	return im.WriteFile(dst)
}

func checkChanges(im *image.Image, orig []byte, allowed []string) error {
	var rs []image.Region
	for _, n := range allowed {
		if r, err := im.Region(n); err == nil {
			rs = append(rs, r)
		}
	}
	for i := range orig {
		if orig[i] == im.Data[i] {
			continue
		}
		ok := false
		for _, r := range rs {
			if uint32(i) >= r.Offset && uint32(i) < r.Offset+r.Size {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("internal error: byte 0x%x outside %s changed; image not written", i, strings.Join(allowed, ", "))
		}
	}
	return nil
}

func printWarnings(w provision.Warnings) {
	for _, s := range w {
		fmt.Fprintln(os.Stderr, "warning:", s)
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func parseKVs(args []string) ([]provision.KV, error) {
	kvs := make([]provision.KV, 0, len(args))
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("expected KEY=VALUE, got %q", a)
		}
		kvs = append(kvs, provision.KV{Key: k, Value: v})
	}
	return kvs, nil
}

func readOptional(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}
