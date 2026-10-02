// Package probe checks URLs and emits probe.<name>.up, probe.<name>.ms, probe.<name>.cert_days (HTTPS)
// and the text probe.<name>.status.
package probe

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/record"
)

// Emit takes probe results.
type Emit func(record.Record)

// Check runs one probe and returns its record.
func Check(ctx context.Context, c *http.Client, p config.Probe, now func() time.Time) record.Record {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Timeout))
	defer cancel()
	start := now()
	up, detail := 0.0, ""
	certDays, hasCert := 0.0, false
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "loglantern-probe")
		var resp *http.Response
		if resp, err = c.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				certDays = resp.TLS.PeerCertificates[0].NotAfter.Sub(now()).Hours() / 24
				hasCert = true
			}
			switch {
			case resp.StatusCode != p.ExpectStatus:
				detail = "status " + resp.Status
			case p.Contains != "" && !strings.Contains(string(body), p.Contains):
				detail = "body lacks expected text"
			default:
				up, detail = 1, "ok"
			}
		}
	}
	if err != nil {
		detail = "error: " + shortErr(err)
	}
	host := p.Host
	if host == "" {
		host = "probe"
	}
	rec := record.Record{Kind: record.KindMetric, TS: now(), Env: p.Env, Host: host, Service: "probe", Synthetic: true,
		Values: map[string]float64{"probe." + p.Name + ".up": up, "probe." + p.Name + ".ms": float64(now().Sub(start).Milliseconds())},
		Texts:  map[string]string{"probe." + p.Name + ".status": detail}}
	if hasCert {
		rec.Values["probe."+p.Name+".cert_days"] = float64(int(certDays*10)) / 10
	}
	return rec
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && strings.Contains(s, "Get ") {
		s = s[i+2:] // drop "Get \"url\": " prefix
	}
	return s
}

// Run starts one loop per probe until ctx ends.
func Run(ctx context.Context, probes []config.Probe, emit Emit) {
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var wg sync.WaitGroup
	for _, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tk := time.NewTicker(time.Duration(p.Interval))
			defer tk.Stop()
			for {
				emit(Check(ctx, c, p, time.Now))
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
				}
			}
		}()
	}
	wg.Wait()
}
