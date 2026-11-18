package cscli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Noz-AF-Angola/sentinela/internal/validate"
)

// Docker is a minimal Docker Engine API client: just enough to run cscli
// inside the CrowdSec container and to send it SIGHUP. Point it at a socket
// proxy that only allows containers + exec, not at the raw socket.
type Docker struct {
	hc   *http.Client
	base string
}

const dockerAPI = "/v1.41"

// NewDocker accepts unix:///var/run/docker.sock, tcp://host:2375 or http(s)://.
func NewDocker(host string) (*Docker, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("invalid docker host %q", host)
	}
	tr := &http.Transport{ResponseHeaderTimeout: 2 * time.Minute}
	base := ""
	switch u.Scheme {
	case "unix":
		path := u.Path
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
		base = "http://docker"
	case "tcp":
		base = "http://" + u.Host
	case "http", "https":
		base = u.Scheme + "://" + u.Host
	default:
		return nil, fmt.Errorf("unsupported docker host scheme %q", u.Scheme)
	}
	return &Docker{hc: &http.Client{Transport: tr}, base: base + dockerAPI}, nil
}

func (d *Docker) post(ctx context.Context, path string, body any) (*http.Response, error) {
	var r io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return d.hc.Do(req)
}

func dockerError(resp *http.Response, what string) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var m struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &m)
	if m.Message == "" {
		m.Message = strings.TrimSpace(string(b))
	}
	return fmt.Errorf("docker %s: HTTP %d: %s", what, resp.StatusCode, m.Message)
}

// Exec runs cmd in container and returns stdout, stderr and the exit code.
func (d *Docker) Exec(ctx context.Context, container string, cmd []string) ([]byte, []byte, int, error) {
	if _, err := validate.Container(container); err != nil {
		return nil, nil, -1, err
	}
	resp, err := d.post(ctx, "/containers/"+url.PathEscape(container)+"/exec", map[string]any{
		"AttachStdout": true, "AttachStderr": true, "Tty": false, "Cmd": cmd,
		"Env": []string{"NO_COLOR=1"},
	})
	if err != nil {
		return nil, nil, -1, fmt.Errorf("docker exec: %w", err)
	}
	var created struct {
		ID string `json:"Id"`
	}
	func() {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusCreated {
			err = dockerError(resp, "exec create")
			return
		}
		err = json.NewDecoder(resp.Body).Decode(&created)
	}()
	if err != nil {
		return nil, nil, -1, err
	}
	if created.ID == "" {
		return nil, nil, -1, errors.New("docker exec: no exec id returned")
	}

	resp, err = d.post(ctx, "/exec/"+url.PathEscape(created.ID)+"/start", map[string]any{"Detach": false, "Tty": false})
	if err != nil {
		return nil, nil, -1, fmt.Errorf("docker exec start: %w", err)
	}
	var stdout, stderr bytes.Buffer
	func() {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			err = dockerError(resp, "exec start")
			return
		}
		err = demux(io.LimitReader(resp.Body, 64<<20), &stdout, &stderr)
	}()
	if err != nil {
		return nil, nil, -1, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/exec/"+url.PathEscape(created.ID)+"/json", nil)
	if err != nil {
		return nil, nil, -1, err
	}
	iresp, err := d.hc.Do(req)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("docker exec inspect: %w", err)
	}
	defer func() { _ = iresp.Body.Close() }()
	if iresp.StatusCode != http.StatusOK {
		return nil, nil, -1, dockerError(iresp, "exec inspect")
	}
	var info struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := json.NewDecoder(iresp.Body).Decode(&info); err != nil {
		return nil, nil, -1, err
	}
	return stdout.Bytes(), stderr.Bytes(), info.ExitCode, nil
}

// Signal sends a signal (e.g. SIGHUP) to the container's main process.
func (d *Docker) Signal(ctx context.Context, container, signal string) error {
	if _, err := validate.Container(container); err != nil {
		return err
	}
	resp, err := d.post(ctx, "/containers/"+url.PathEscape(container)+"/kill?signal="+url.QueryEscape(signal), nil)
	if err != nil {
		return fmt.Errorf("docker kill: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return dockerError(resp, "kill")
	}
	return nil
}

// demux splits Docker's multiplexed stream: an 8-byte header (stream type,
// three zero bytes, big-endian payload size) before each chunk.
func demux(r io.Reader, stdout, stderr io.Writer) error {
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("docker stream: %w", err)
		}
		size := int64(binary.BigEndian.Uint32(hdr[4:]))
		var w io.Writer
		switch hdr[0] {
		case 1:
			w = stdout
		case 2:
			w = stderr
		default:
			w = io.Discard
		}
		if _, err := io.CopyN(w, r, size); err != nil {
			return fmt.Errorf("docker stream: %w", err)
		}
	}
}

// DockerRunner runs cscli inside a container through the Engine API.
type DockerRunner struct {
	Docker    *Docker
	Container string
	Command   []string // defaults to ["cscli"]
}

// Run implements Runner.
func (d DockerRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	base := d.Command
	if len(base) == 0 {
		base = []string{"cscli"}
	}
	out, errOut, code, err := d.Docker.Exec(ctx, d.Container, append(append([]string{}, base...), args...))
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, commandError(args, fmt.Errorf("exit status %d", code), string(errOut))
	}
	return out, nil
}

// DockerReloader sends SIGHUP to the CrowdSec container, which makes
// CrowdSec reload its configuration and hub items.
type DockerReloader struct {
	Docker    *Docker
	Container string
}

// Reload implements Reloader.
func (d DockerReloader) Reload(ctx context.Context) error {
	return d.Docker.Signal(ctx, d.Container, "SIGHUP")
}
