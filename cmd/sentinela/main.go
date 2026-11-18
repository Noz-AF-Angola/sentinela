// Command sentinela is a small web interface for CrowdSec.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Noz-AF-Angola/sentinela/internal/auth"
	"github.com/Noz-AF-Angola/sentinela/internal/config"
	"github.com/Noz-AF-Angola/sentinela/internal/cscli"
	"github.com/Noz-AF-Angola/sentinela/internal/demo"
	"github.com/Noz-AF-Angola/sentinela/internal/lapi"
	"github.com/Noz-AF-Angola/sentinela/internal/metrics"
	"github.com/Noz-AF-Angola/sentinela/internal/web"
)

var version = "dev"

const usage = `Sentinela - a small web interface for CrowdSec

Usage:
  sentinela [serve]          run the web server (configured with SENTINELA_* variables)
  sentinela hash-password    read a password on stdin, print a bcrypt hash for the users file
  sentinela totp-secret USER print a new TOTP secret and its otpauth:// URI
  sentinela healthcheck      exit 0 if the local server answers on /healthz (for Docker)
  sentinela demo             run with fake data on 127.0.0.1:8080 (no CrowdSec needed)
  sentinela version          print the version
`

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(logger)
	case "hash-password":
		err = hashPassword(os.Stdin, os.Stdout)
	case "totp-secret":
		err = totpSecret(os.Args[2:], os.Stdout)
	case "healthcheck":
		err = healthcheck(os.Getenv("SENTINELA_LISTEN"))
	case "demo":
		err = runDemo(logger, os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentinela:", err)
		os.Exit(1)
	}
}

func serve(logger *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	opt := web.Options{
		ReadOnly: cfg.ReadOnly, CookieSecure: cfg.CookieSecure, SessionTTL: cfg.SessionTTL,
		Version: version, Logger: logger, Trusted: auth.Trusted(cfg.TrustedProxies), LogoutURL: cfg.ProxyLogoutURL,
	}
	switch cfg.AuthMode {
	case config.AuthLocal:
		users, err := auth.LoadUsersFile(cfg.UsersFile)
		if err != nil {
			return fmt.Errorf("users file: %w", err)
		}
		opt.Directory = auth.NewDirectory(users)
		logger.Info("authentication", "mode", "local", "users", len(users))
	case config.AuthProxy:
		opt.Proxy = &auth.ProxyIdentity{
			Trusted: opt.Trusted, UserHeader: cfg.ProxyUserHeader,
			GroupHeader: cfg.ProxyGroupsHeader, AdminGroup: cfg.ProxyAdminGroup,
		}
		logger.Info("authentication", "mode", "proxy", "header", cfg.ProxyUserHeader, "trusted", len(cfg.TrustedProxies))
	}

	if cfg.LAPIURL != "" {
		hc := &http.Client{Timeout: 20 * time.Second}
		if cfg.LAPICAFile != "" {
			pem, err := os.ReadFile(cfg.LAPICAFile)
			if err != nil {
				return fmt.Errorf("LAPI CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return errors.New("LAPI CA file: no certificate found")
			}
			hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
		}
		c, err := lapi.New(cfg.LAPIURL, cfg.LAPIMachineID, cfg.LAPIPassword, hc)
		if err != nil {
			return err
		}
		opt.LAPI = c
	}
	if cfg.MetricsURL != "" {
		opt.Metrics = &metrics.Fetcher{URL: cfg.MetricsURL}
	}
	switch cfg.CSCLIMode {
	case config.CSCLIExec:
		var rl cscli.Reloader
		if len(cfg.ReloadCommand) > 0 {
			rl = cscli.ExecReloader{Command: cfg.ReloadCommand}
		}
		opt.CSCLI = cscli.New(cscli.ExecRunner{Command: cfg.CSCLICommand}, rl)
	case config.CSCLIDocker:
		d, err := cscli.NewDocker(cfg.DockerHost)
		if err != nil {
			return err
		}
		opt.CSCLI = cscli.New(
			cscli.DockerRunner{Docker: d, Container: cfg.DockerContainer, Command: cfg.CSCLICommand},
			cscli.DockerReloader{Docker: d, Container: cfg.DockerContainer},
		)
	}
	logger.Info("backends", "lapi", cfg.LAPIURL != "", "metrics", cfg.MetricsURL != "", "cscli", cfg.CSCLIMode, "read_only", cfg.ReadOnly)

	srv, err := web.New(opt)
	if err != nil {
		return err
	}
	return listen(logger, cfg.Listen, srv)
}

func listen(logger *slog.Logger, addr string, h http.Handler) error {
	hs := &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 5 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	logger.Info("listening", "addr", addr, "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shut)
}

func hashPassword(in io.Reader, out io.Writer) error {
	fmt.Fprintln(os.Stderr, "Type the password and press Enter (input is echoed; to hide it, use: read -rs PW; echo \"$PW\" | sentinela hash-password)")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	h, err := auth.HashPassword(strings.TrimRight(line, "\r\n"))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, h)
	return err
}

func totpSecret(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("totp-secret", flag.ContinueOnError)
	issuer := fs.String("issuer", "Sentinela", "issuer name shown in the authenticator app")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: sentinela totp-secret [-issuer NAME] USER")
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "secret: %s\nuri:    %s\n\nAppend \":%s\" to the user's line in the users file.\n",
		secret, auth.TOTPURI(*issuer, fs.Arg(0), secret), secret)
	return err
}

func healthcheck(listen string) error {
	port := "8080"
	if i := strings.LastIndex(listen, ":"); i >= 0 && i < len(listen)-1 {
		port = listen[i+1:]
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port in SENTINELA_LISTEN: %q", port)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(n)+"/healthz", nil) //nolint:gosec // loopback, numeric port.
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // fixed loopback URL with a numeric port.
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

func runDemo(logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	addr := fs.String("listen", "127.0.0.1:8080", "address to listen on (keep it on localhost)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	password := os.Getenv("SENTINELA_DEMO_PASSWORD")
	if password == "" {
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			return err
		}
		password = strings.ToLower(secret[:16])
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	users, err := auth.ParseUsers(strings.NewReader("demo:admin:" + hash + "\n"))
	if err != nil {
		return err
	}
	b := demo.New()
	srv, err := web.New(web.Options{
		LAPI: b, Metrics: b, CSCLI: b, Directory: auth.NewDirectory(users),
		Version: version, Logger: logger, Banner: "Demo mode: fake data, nothing here touches a real CrowdSec.",
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nDemo running on http://%s  -  user: demo  password: %s\n\n", *addr, password)
	return listen(logger, *addr, srv)
}
