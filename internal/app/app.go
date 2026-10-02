// Package app wires the pipeline: ingest → (registry, rules, batched writer) → incidents → outbox → notifiers.
package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/thomkin/loglantern/internal/ai"
	"github.com/thomkin/loglantern/internal/api"
	"github.com/thomkin/loglantern/internal/auth"
	"github.com/thomkin/loglantern/internal/config"
	"github.com/thomkin/loglantern/internal/hosts"
	"github.com/thomkin/loglantern/internal/incident"
	"github.com/thomkin/loglantern/internal/ingest"
	"github.com/thomkin/loglantern/internal/lightsail"
	"github.com/thomkin/loglantern/internal/notify"
	"github.com/thomkin/loglantern/internal/probe"
	"github.com/thomkin/loglantern/internal/record"
	"github.com/thomkin/loglantern/internal/report"
	"github.com/thomkin/loglantern/internal/rules"
	"github.com/thomkin/loglantern/internal/store"
)

const (
	flushEvery = time.Second
	flushSize  = 2000
	queueSize  = 512 // ingest batches waiting for the processor
)

// App is one running loglantern.
type App struct {
	cfg    *config.Config
	log    *slog.Logger
	st     *store.Store
	reg    *hosts.Registry
	eng    *rules.Engine
	mgr    *incident.Manager
	hub    *api.Hub
	sender *notify.Sender
	ing    *ingest.Handler
	api    *api.Server
	envs   []string
	agents *ai.Agents // nil when AI is off
	out    *notify.Outbox
	bgWork sync.WaitGroup

	in   chan []record.Record
	wake chan struct{}
	buf  []record.Record

	// Now is the clock (tests).
	Now func() time.Time
	// Notifiers can be replaced before Run (tests).
	Notifiers map[string]notify.Notifier

	mu        sync.Mutex
	lastWrite time.Time
	written   int64
}

// New opens the database and restores state (registry, open incidents, 2 h window).
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, error) {
	a := &App{cfg: cfg, log: log, in: make(chan []record.Record, queueSize), wake: make(chan struct{}, 1), Now: time.Now, hub: api.NewHub()}
	for e := range cfg.Envs {
		a.envs = append(a.envs, e)
	}
	slices.Sort(a.envs)
	st, err := store.Open(cfg.Storage.Path, cfg.Storage.CacheMB)
	if err != nil {
		return nil, err
	}
	a.st = st
	a.out = notify.NewOutbox(st, cfg)
	if err := a.restore(ctx); err != nil {
		_ = st.Close()
		return nil, err
	}
	var enrich incident.Enricher
	if cfg.AIEnabled() {
		a.agents = ai.NewAgents(cfg, st)
		enrich = a.agents.Incident
		var names []string
		for _, ag := range cfg.AI.Agents {
			names = append(names, ag.Name+"("+ag.On+", "+ag.Model+")")
		}
		log.Info("ai agents on", "agents", names)
	}
	a.mgr = incident.New(st, cfg, a.reg.Role, enrich, log)
	a.Notifiers = notify.FromConfig(cfg)
	if a.ing, err = ingest.New(cfg, a.sink, log); err != nil {
		_ = st.Close()
		return nil, err
	}
	au, err := auth.New(cfg)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	a.api = api.New(st, au, a.hub, cfg.CORS, a.health, log)
	return a, nil
}

func (a *App) restore(ctx context.Context) error {
	now := a.Now()
	saved, err := a.st.Hosts(ctx, nil)
	if err != nil {
		return fmt.Errorf("restore hosts: %w", err)
	}
	var known []store.Host
	for _, h := range a.cfg.Hosts {
		known = append(known, store.Host{Env: h.Env, Host: h.Host, Role: h.Role})
	}
	a.reg = hosts.New(known, saved, time.Duration(a.cfg.MissingAfter), now)
	if a.eng, err = rules.New(a.cfg.Rules, time.Duration(a.cfg.Window), a.reg.Role); err != nil {
		return err
	}
	open, err := a.st.OpenIncidentKeys(ctx)
	if err != nil {
		return fmt.Errorf("restore incidents: %w", err)
	}
	var keys []string
	for k := range open {
		if !strings.HasPrefix(k, incident.HostRule+"/") {
			keys = append(keys, k)
		}
	}
	a.eng.SetActive(keys)
	n := 0
	if err := a.st.ValuesSince(ctx, now.Add(-time.Duration(a.cfg.Window)), func(v store.SeriesValue) {
		n++
		if v.IsText {
			a.eng.ObserveText(v.Env, v.Host, v.Name, v.T, v.Text)
		} else {
			a.eng.ObserveValue(v.Env, v.Host, v.Name, v.T, v.V)
		}
	}); err != nil {
		return fmt.Errorf("restore window: %w", err)
	}
	if err := a.st.LastSeen(ctx, a.eng.AbsentSeries(), a.eng.ObserveSeen); err != nil {
		return fmt.Errorf("restore last seen: %w", err)
	}
	var per time.Duration // logs are only needed for lograte rules
	for _, r := range a.cfg.Rules {
		if r.Type == config.RuleLogRate {
			per = max(per, time.Duration(r.Per))
		}
	}
	if per > 0 {
		if err := a.st.LogsSince(ctx, now.Add(-per), func(l store.LogLine) {
			n++
			a.eng.ObserveLog(l.Env, l.Host, l.Service, l.Level, l.Message, l.TS)
		}); err != nil {
			return fmt.Errorf("restore logs: %w", err)
		}
	}
	a.log.Info("state restored", "hosts", len(saved), "open_incidents", len(open), "window_points", n)
	return nil
}

// sink is called by the ingest handler; a full queue makes Fluent Bit retry.
func (a *App) sink(recs []record.Record) error {
	select {
	case a.in <- recs:
		return nil
	default:
		return ingest.ErrBusy
	}
}

// emit is used by probes and the Lightsail poller.
func (a *App) emit(ctx context.Context) func(record.Record) {
	return func(r record.Record) {
		select {
		case a.in <- []record.Record{r}:
		case <-ctx.Done():
		}
	}
}

// IngestHandler serves Fluent Bit.
func (a *App) IngestHandler() http.Handler {
	mux := http.NewServeMux()
	a.ing.Routes(mux)
	return mux
}

// APIHandler serves dashboards.
func (a *App) APIHandler() http.Handler { return a.api.Handler() }

func (a *App) health(ctx context.Context) map[string]any {
	pending, _ := a.st.PendingCount(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	s := &a.ing.Stats
	return map[string]any{
		"outbox_pending": pending, "queue": len(a.in), "sse_clients": a.hub.Count(),
		"records_written": a.written, "last_write": a.lastWrite,
		"ingest": map[string]int64{"requests": s.Requests.Load(), "records": s.Records.Load(), "invalid": s.Invalid.Load(), "rejected": s.Rejected.Load(), "busy": s.Busy.Load()},
	}
}

// Run serves on the listeners (either may be nil) and processes until ctx ends.
func (a *App) Run(ctx context.Context, ingestLn, apiLn net.Listener) error {
	defer a.st.Close()
	var wg sync.WaitGroup
	var servers []*http.Server
	serve := func(ln net.Listener, h http.Handler, write time.Duration) {
		if ln == nil {
			return
		}
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: write, IdleTimeout: 2 * time.Minute}
		servers = append(servers, srv)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				a.log.Error("http", "addr", ln.Addr().String(), "err", err)
			}
		}()
	}
	serve(ingestLn, a.IngestHandler(), time.Minute)
	serve(apiLn, a.APIHandler(), 0) // SSE streams stay open

	bg, stopBg := context.WithCancel(context.Background())
	a.sender = notify.NewSender(a.st, a.cfg, a.Notifiers, a.log)
	a.sender.Now = a.Now
	var bgw sync.WaitGroup
	start := func(f func()) {
		bgw.Add(1)
		go func() { defer bgw.Done(); f() }()
	}
	start(func() { a.sender.Run(bg, a.wake) })
	if len(a.cfg.Probes) > 0 {
		start(func() { probe.Run(bg, a.cfg.Probes, a.emit(bg)) })
	}
	if a.cfg.LightsailEnabled() {
		p := lightsail.New(a.cfg, a.log)
		start(func() { p.Run(bg, time.Duration(a.cfg.Lightsail.Interval), a.emit(bg)) })
		a.log.Info("lightsail poller on", "regions", a.cfg.Lightsail.Regions)
	} else if a.cfg.Lightsail != nil {
		a.log.Info("lightsail poller off: credentials not set")
	}

	a.loop(ctx)

	// shutdown: stop accepting, drain the queue, flush, then stop background work
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	wg.Wait()
	stopBg()
	bgw.Wait()
	a.drain(sctx)
	a.mgr.Wait()
	a.bgWork.Wait()
	a.log.Info("stopped")
	return nil
}

func (a *App) loop(ctx context.Context) {
	tick := time.NewTicker(time.Duration(a.cfg.Tick))
	flush := time.NewTicker(flushEvery)
	retain := time.NewTicker(time.Hour)
	defer tick.Stop()
	defer flush.Stop()
	defer retain.Stop()
	a.retain(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case recs := <-a.in:
			a.take(recs)
			if len(a.buf) >= flushSize {
				a.flush(ctx)
			}
		case <-flush.C:
			a.flush(ctx)
		case <-tick.C:
			a.Tick(ctx)
		case <-retain.C:
			a.retain(ctx)
		}
	}
}

func (a *App) take(recs []record.Record) {
	for _, r := range recs {
		a.reg.Seen(r)
		a.eng.Observe(r)
	}
	a.buf = append(a.buf, recs...)
}

func (a *App) drain(ctx context.Context) {
	for {
		select {
		case recs := <-a.in:
			a.take(recs)
		default:
			a.flush(ctx)
			if err := a.st.SaveHosts(ctx, a.reg.Snapshot()); err != nil {
				a.log.Error("save hosts", "err", err)
			}
			return
		}
	}
}

func (a *App) flush(ctx context.Context) {
	if len(a.buf) == 0 {
		return
	}
	if err := a.st.Write(ctx, a.buf); err != nil {
		a.log.Error("write", "records", len(a.buf), "err", err)
		if len(a.buf) < 50*flushSize {
			return // keep and retry next flush
		}
		a.log.Error("dropping records after repeated write errors", "records", len(a.buf))
	} else {
		a.mu.Lock()
		a.written += int64(len(a.buf))
		a.lastWrite = a.Now()
		a.mu.Unlock()
	}
	a.buf = a.buf[:0]
}

// Tick evaluates rules and heartbeats once (exported for tests).
func (a *App) Tick(ctx context.Context) {
	a.flush(ctx) // incidents and AI context see the latest data
	now := a.Now()
	changes := a.reg.Check(now)
	ts := append(incident.HostTransitions(changes), a.eng.Evaluate(now)...)
	if len(ts) > 0 {
		if err := a.mgr.Handle(ctx, ts, now); err != nil {
			a.log.Error("incidents", "err", err)
		}
		for _, t := range ts {
			a.hub.Publish("incident", t.Env, t)
		}
		select {
		case a.wake <- struct{}{}:
		default:
		}
	}
	if err := a.mgr.Sweep(ctx, now); err != nil {
		a.log.Error("incident sweep", "err", err)
	}
	if len(changes) > 0 {
		for _, c := range changes {
			a.hub.Publish("host", c.Env, c)
		}
	}
	if err := a.st.SaveHosts(ctx, a.reg.Snapshot()); err != nil {
		a.log.Error("save hosts", "err", err)
	}
	if r := a.cfg.Report; r != nil {
		if due, err := report.Due(ctx, a.st, r.At, r.Location(), now); err != nil {
			a.log.Error("report", "err", err)
		} else if due {
			text, err := report.Send(ctx, a.st, a.out, a.envs, r.Route, r.Location(), now)
			if err != nil {
				a.log.Error("report", "err", err)
			} else if a.agents != nil && a.agents.Has(config.OnDailyReport) {
				a.reviewReport(text, r.Route)
			}
		}
	}
}

// reviewReport runs the daily_report agents in the background and queues their answers.
func (a *App) reviewReport(text, route string) {
	a.bgWork.Add(1)
	go func() {
		defer a.bgWork.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		notes, err := a.agents.Report(ctx, text)
		if err != nil {
			a.log.Warn("ai report", "err", err)
		}
		for _, n := range notes {
			to := cmp.Or(n.Route, route)
			if err := a.out.Put(ctx, to, "[AI "+n.Agent+"] "+n.Text, 0, false, time.Now()); err != nil {
				a.log.Warn("ai report message", "err", err)
			}
		}
	}()
}

func (a *App) retain(ctx context.Context) {
	r := a.cfg.Storage.Retention
	n, err := a.st.Retain(ctx, a.Now(), store.Retention{Logs: time.Duration(r.Logs), Metrics: time.Duration(r.Metrics),
		Counters: time.Duration(r.Counters), Incidents: time.Duration(r.Incidents)})
	if err != nil {
		a.log.Error("retention", "err", err)
		return
	}
	if n > 0 {
		a.log.Info("retention", "deleted", n)
	}
}
