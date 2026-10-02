// Command loglantern receives logs and metrics from Fluent Bit, raises alerts and serves a dashboard API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/thomkin/loglantern/internal/app"
	"github.com/thomkin/loglantern/internal/auth"
	"github.com/thomkin/loglantern/internal/config"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/loglantern/config.yaml", "config file")
	level := flag.String("log-level", "info", "debug, info, warn or error")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: loglantern [flags] [run|check-config|version]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	cmd := "run"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(*level)); err != nil {
		fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))

	switch cmd {
	case "version":
		fmt.Println(version)
		return
	case "check-config":
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fatal(err)
		}
		if _, err := auth.New(cfg); err != nil { // loads the JWT public keys
			fatal(err)
		}
		summary(cfg)
		return
	case "run":
	default:
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		fatal(err)
	}
	ingestLn, err := net.Listen("tcp", cfg.Listen.Ingest)
	if err != nil {
		fatal(err)
	}
	apiLn, err := net.Listen("tcp", cfg.Listen.API)
	if err != nil {
		fatal(err)
	}
	log.Info("loglantern started", "version", version, "ingest", cfg.Listen.Ingest, "api", cfg.Listen.API, "db", cfg.Storage.Path)
	if err := a.Run(ctx, ingestLn, apiLn); err != nil {
		fatal(err)
	}
}

// summary prints what the config enables, without secrets.
func summary(c *config.Config) {
	var envs []string
	for e := range c.Envs {
		envs = append(envs, e)
	}
	sort.Strings(envs)
	on := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	var notifiers []string
	if c.Notifiers.Telegram != nil {
		notifiers = append(notifiers, "telegram")
	}
	if c.Notifiers.Webhook != nil {
		notifiers = append(notifiers, "webhook")
	}
	ai := on(c.AIEnabled())
	if c.AI != nil {
		var names []string
		for _, a := range c.AI.Agents {
			names = append(names, a.Name+" ("+a.On+", "+a.Model+")")
		}
		ai += ", agents: " + strings.Join(names, ", ")
	}
	fmt.Printf("config ok\nenvs: %v\nknown hosts: %d\nrules: %d\nroutes: %d\nnotifiers: %v\nprobes: %d\nai: %s\nlightsail: %s\nreport: %s\napi keys: %d, jwt issuers: %d\n",
		envs, len(c.Hosts), len(c.Rules), len(c.Routes), notifiers, len(c.Probes), ai, on(c.LightsailEnabled()), on(c.Report != nil),
		len(c.Auth.APIKeys), len(c.Auth.JWT))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "loglantern:", err)
	os.Exit(1)
}
