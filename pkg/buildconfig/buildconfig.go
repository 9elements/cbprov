// Package buildconfig parses the Kconfig .config that coreboot stores in
// CBFS as "config" (CONFIG_INCLUDE_CONFIG_FILE).
package buildconfig

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// FileName is the CBFS file holding the build configuration.
const FileName = "config"

// Config maps option names without the CONFIG_ prefix to raw values.
// Options set to "n" ("# CONFIG_X is not set") are absent.
type Config map[string]string

// Parse reads .config syntax.
func Parse(b []byte) Config {
	c := Config{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "CONFIG_") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "CONFIG_"), "=")
		if !ok {
			continue
		}
		c[k] = v
	}
	return c
}

// Bool reports whether a bool option is enabled.
func (c Config) Bool(name string) bool { return c[name] == "y" }

// String returns a string option without quotes.
func (c Config) String(name string) string {
	v := c[name]
	if u, err := strconv.Unquote(v); err == nil {
		return u
	}
	return v
}

// Int returns an int or hex option, or def if unset or invalid.
func (c Config) Int(name string, def int) int {
	v, ok := c[name]
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 0, 64)
	if err != nil {
		return def
	}
	return int(n)
}
