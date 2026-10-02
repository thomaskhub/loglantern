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
	"time"
	_ "time/tzdata" // maintenance and report time zones on minimal images

	"github.com/thomaskhub/loglantern/internal/app"
	"github.com/thomaskhub/loglantern/internal/auth"
	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/rules"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/loglantern/config.yaml", "config file")
	level := flag.String("log-level", "info", "debug, info, warn or error")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: loglantern [flags] [run|check-config|version]\n\nSIGHUP reloads the config (listen addresses and storage.path need a restart).\n\n")
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
	ingestLn, err := net.Listen("tcp", cfg.Listen.Ingest)
	if err != nil {
		fatal(err)
	}
	apiLn, err := net.Listen("tcp", cfg.Listen.API)
	if err != nil {
		fatal(err)
	}
	ingest, api := newHandoff(ingestLn), newHandoff(apiLn)
	defer ingest.Close()
	defer api.Close()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	log.Info("loglantern started", "version", version, "ingest", cfg.Listen.Ingest, "api", cfg.Listen.API, "db", cfg.Storage.Path)
	for {
		a, err := app.New(ctx, cfg, log)
		if err != nil {
			fatal(err)
		}
		genCtx, next := context.WithCancel(ctx)
		go func() {
			for {
				select {
				case <-genCtx.Done():
					return
				case <-hup:
				}
				newCfg, err := reload(*cfgPath, cfg)
				if err != nil {
					log.Error("reload rejected, keeping the running config", "err", err)
					continue
				}
				log.Info("reloading config")
				cfg = newCfg
				next()
				return
			}
		}()
		if err := a.Run(genCtx, ingest.generation(), api.generation()); err != nil {
			fatal(err)
		}
		next()
		if ctx.Err() != nil {
			return
		}
		log.Info("config reloaded")
	}
}

// reload loads and checks a new config; listen addresses and the database path need a restart.
func reload(path string, old *config.Config) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if c.Listen != old.Listen || c.Storage.Path != old.Storage.Path {
		return nil, fmt.Errorf("listen and storage.path cannot change on reload; restart instead")
	}
	if _, err := auth.New(c); err != nil {
		return nil, err
	}
	if _, err := rules.New(c.Rules, time.Duration(c.Window), nil); err != nil {
		return nil, err
	}
	return c, nil
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
	for name, n := range c.Notifiers {
		notifiers = append(notifiers, name+" ("+n.Type()+")")
	}
	sort.Strings(notifiers)
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
