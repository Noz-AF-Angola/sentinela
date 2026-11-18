// Package cscli runs a fixed set of cscli commands and decodes their JSON
// output. Commands are always executed as an argument vector, never through a
// shell, and every user-supplied argument is validated before it gets here.
package cscli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes cscli with the given arguments and returns its stdout.
type Runner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

// Reloader asks CrowdSec to reload its configuration (after hub changes).
type Reloader interface {
	Reload(ctx context.Context) error
}

// ExecRunner runs a local command, for example ["cscli"] or
// ["sudo", "-n", "/usr/bin/cscli"].
type ExecRunner struct {
	Command []string
}

// Run implements Runner.
func (e ExecRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if len(e.Command) == 0 {
		return nil, errors.New("cscli command is not configured")
	}
	argv := append(append([]string{}, e.Command[1:]...), args...)
	cmd := exec.CommandContext(ctx, e.Command[0], argv...) //nolint:gosec // fixed binary from config, validated args, no shell.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{buf: &stdout, max: 64 << 20}
	cmd.Stderr = &limitedBuffer{buf: &stderr, max: 64 << 10}
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "NO_COLOR=1"}
	if err := cmd.Run(); err != nil {
		return nil, commandError(args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// ExecReloader runs a local command such as ["sudo","-n","systemctl","reload","crowdsec"].
type ExecReloader struct {
	Command []string
}

// Reload implements Reloader.
func (e ExecReloader) Reload(ctx context.Context) error {
	if len(e.Command) == 0 {
		return errors.New("reload command is not configured")
	}
	cmd := exec.CommandContext(ctx, e.Command[0], e.Command[1:]...) //nolint:gosec // fixed command from config.
	var stderr bytes.Buffer
	cmd.Stderr = &limitedBuffer{buf: &stderr, max: 64 << 10}
	if err := cmd.Run(); err != nil {
		return commandError(e.Command, err, stderr.String())
	}
	return nil
}

func commandError(args []string, err error, stderr string) error {
	msg := strings.TrimSpace(stderr)
	if len(msg) > 600 {
		msg = msg[:600] + "…"
	}
	name := "cscli"
	if len(args) > 0 {
		name += " " + args[0]
		if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
			name += " " + args[1]
		}
	}
	if msg == "" {
		return fmt.Errorf("%s: %w", name, err)
	}
	return fmt.Errorf("%s: %w: %s", name, err, msg)
}

type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	room := l.max - l.buf.Len()
	if room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}
