// Package qemu boots coreboot images in QEMU for cbprov's end-to-end tests.
// It captures the serial console and reads guest memory (coreboot table,
// SMBIOS) and the post-boot flash contents.
package qemu

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Arch selects the emulated machine.
type Arch string

const (
	Q35     Arch = "q35"
	I440FX  Arch = "i440fx"
	AArch64 Arch = "aarch64"
)

// MemSize is the guest RAM size in MiB.
const MemSize = 1024

// ErrNoFlash is returned by Flash for machines that boot from a read-only ROM.
var ErrNoFlash = errors.New("machine has no writable flash")

// Options configure a boot.
type Options struct {
	ROM  string
	Arch Arch
	// Timeout for reaching all ExpectSerial markers (default 60s).
	Timeout time.Duration
	// ExpectSerial lists substrings that must all appear on the serial console.
	// Boot returns once they did; the VM is then paused for memory reads.
	ExpectSerial []string
	// FailSerial lists substrings that abort the boot with an error.
	FailSerial []string
	// Log receives the raw serial output as it arrives (optional).
	Log io.Writer
	// QEMU overrides the qemu-system binary.
	QEMU string
	// ExtraArgs are appended to the QEMU command line.
	ExtraArgs []string
}

// Binary returns the qemu-system binary for arch.
func Binary(a Arch) string {
	if a == AArch64 {
		return "qemu-system-aarch64"
	}
	return "qemu-system-x86_64"
}

// Available reports whether QEMU for arch is installed.
func Available(a Arch) bool {
	_, err := exec.LookPath(Binary(a))
	return err == nil
}

// Machine is a booted (and paused) QEMU instance.
type Machine struct {
	arch  Arch
	dir   string
	flash string
	cmd   *exec.Cmd
	q     *qmp
	exit  chan struct{}

	mu     sync.Mutex
	serial bytes.Buffer
	stderr bytes.Buffer
	notify chan struct{}

	closeOnce sync.Once
	closeErr  error
	flashData []byte
}

func (o *Options) args(dir string) ([]string, string, error) {
	accel := os.Getenv("CBPROV_QEMU_ACCEL")
	if accel == "" {
		accel = "tcg"
	}
	a := []string{
		"-nodefaults", "-display", "none", "-no-reboot",
		"-serial", "stdio", "-monitor", "none",
		"-qmp", "unix:" + filepath.Join(dir, "qmp.sock") + ",server=on,wait=off",
		"-m", fmt.Sprintf("%dM", MemSize), "-accel", accel,
	}
	flash := ""
	switch o.Arch {
	case Q35, I440FX:
		m := "q35"
		if o.Arch == I440FX {
			m = "pc"
		}
		// pflash, unlike -bios, lets the guest write SMMSTORE.
		flash = filepath.Join(dir, "flash.bin")
		if err := copyFile(o.ROM, flash); err != nil {
			return nil, "", err
		}
		a = append(a, "-machine", m, "-drive", "if=pflash,format=raw,file="+flash)
	case AArch64:
		a = append(a, "-machine", "virt,secure=on,virtualization=on", "-cpu", "cortex-a53", "-bios", o.ROM)
	default:
		return nil, "", fmt.Errorf("unknown arch %q", o.Arch)
	}
	return append(a, o.ExtraArgs...), flash, nil
}

// Boot starts QEMU and waits until all ExpectSerial markers appeared. On
// error the returned Machine (if non-nil) still holds the serial log; callers
// must Close it either way.
func Boot(ctx context.Context, o Options) (*Machine, error) {
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	if _, err := os.Stat(o.ROM); err != nil {
		return nil, err
	}
	bin := o.QEMU
	if bin == "" {
		bin = Binary(o.Arch)
	}
	// Short path: unix socket paths are limited to 108 bytes.
	dir, err := os.MkdirTemp("", "cbprov-qemu")
	if err != nil {
		return nil, err
	}
	args, flash, err := o.args(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	m := &Machine{arch: o.Arch, dir: dir, flash: flash, exit: make(chan struct{}), notify: make(chan struct{}, 1)}
	m.cmd = exec.Command(bin, args...)
	m.cmd.Stderr = lockedWriter{&m.mu, &m.stderr}
	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	if err := m.cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	readerDone := make(chan struct{})
	go m.readSerial(stdout, o.Log, readerDone)
	go func() {
		<-readerDone
		m.cmd.Wait()
		close(m.exit)
	}()

	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	if m.q, err = dialQMP(ctx, filepath.Join(dir, "qmp.sock")); err != nil {
		return m, m.fail(err)
	}
	if err := m.wait(ctx, o.ExpectSerial, o.FailSerial); err != nil {
		return m, m.fail(err)
	}
	if _, err := m.q.run("stop", nil); err != nil {
		return m, m.fail(err)
	}
	return m, nil
}

func (m *Machine) wait(ctx context.Context, expect, fail []string) error {
	for {
		s := m.Serial()
		for _, f := range fail {
			if strings.Contains(s, f) {
				return fmt.Errorf("serial shows failure marker %q", f)
			}
		}
		missing := ""
		for _, e := range expect {
			if !strings.Contains(s, e) {
				missing = e
				break
			}
		}
		if missing == "" {
			return nil
		}
		select {
		case <-m.notify:
		case <-m.exit:
			if s = m.Serial(); !containsAll(s, expect) {
				return fmt.Errorf("qemu exited before %q appeared", missing)
			}
		case <-ctx.Done():
			return fmt.Errorf("waiting for %q: %w", missing, ctx.Err())
		}
	}
}

func containsAll(s string, subs []string) bool {
	for _, e := range subs {
		if !strings.Contains(s, e) {
			return false
		}
	}
	return true
}

func (m *Machine) fail(err error) error {
	return fmt.Errorf("%w\n--- qemu stderr ---\n%s--- serial (tail) ---\n%s", err, m.Stderr(), tail(m.Serial(), 40))
}

func tail(s string, n int) string {
	lines := strings.SplitAfter(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "")
}

func (m *Machine) readSerial(r io.Reader, log io.Writer, done chan struct{}) {
	defer close(done)
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			m.mu.Lock()
			m.serial.Write(buf[:n])
			m.mu.Unlock()
			if log != nil {
				log.Write(buf[:n])
			}
			select {
			case m.notify <- struct{}{}:
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// Serial returns the serial output so far, with ANSI escapes and CRs removed.
func (m *Machine) Serial() string {
	return strings.ReplaceAll(ansi.ReplaceAllString(m.RawSerial(), ""), "\r", "")
}

// RawSerial returns the serial output exactly as received.
func (m *Machine) RawSerial() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.serial.String()
}

// Stderr returns QEMU's own stderr output.
func (m *Machine) Stderr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stderr.String()
}

// ReadMem reads guest physical memory.
func (m *Machine) ReadMem(addr uint64, n int) ([]byte, error) {
	if m.q == nil {
		return nil, errors.New("no QMP connection")
	}
	f := filepath.Join(m.dir, "mem.bin")
	defer os.Remove(f)
	if _, err := m.q.run("pmemsave", map[string]any{"val": addr, "size": n, "filename": f}); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("pmemsave returned %d of %d bytes", len(b), n)
	}
	return b, nil
}

// Close stops QEMU and removes its temporary files. It keeps the flash
// contents for Flash.
func (m *Machine) Close() error {
	m.closeOnce.Do(func() {
		if m.q != nil {
			m.q.run("quit", nil)
			m.q.close()
		}
		select {
		case <-m.exit:
		case <-time.After(10 * time.Second):
			m.cmd.Process.Kill()
			<-m.exit
		}
		if m.flash != "" {
			m.flashData, m.closeErr = os.ReadFile(m.flash)
		}
		if err := os.RemoveAll(m.dir); m.closeErr == nil {
			m.closeErr = err
		}
	})
	return m.closeErr
}

// Flash returns the flash contents after the guest ran (it may have written
// SMMSTORE). It closes the machine first.
func (m *Machine) Flash() ([]byte, error) {
	if err := m.Close(); err != nil {
		return nil, err
	}
	if m.flash == "" {
		return nil, ErrNoFlash
	}
	return m.flashData, nil
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}
