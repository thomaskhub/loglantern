package config

import (
	"strings"
	"testing"
	"time"
)

const minimal = `
envs:
  uat: {ingest_token_env: LL_TOK_UAT}
`

func TestParse(t *testing.T) {
	t.Setenv("LL_TOK_UAT", "tok")
	tests := []struct {
		name    string
		yaml    string
		env     map[string]string
		wantErr string
		check   func(t *testing.T, c *Config)
	}{
		{name: "C1_defaults", yaml: minimal, check: func(t *testing.T, c *Config) {
			if c.Storage.Retention.Logs.D() != 120*time.Hour || c.Storage.Retention.Incidents.D() != 2160*time.Hour {
				t.Errorf("retention defaults: %+v", c.Storage.Retention)
			}
			if c.MissingAfter.D() != 3*time.Minute || c.Window.D() != 2*time.Hour || c.Listen.API != "127.0.0.1:8441" {
				t.Errorf("defaults: %+v", c)
			}
			if c.AIEnabled() || c.LightsailEnabled() {
				t.Error("optional parts enabled without config")
			}
		}},
		{name: "C2_unknown_field", yaml: minimal + "bogus: 1\n", wantErr: "field bogus not found"},
		{name: "C3_empty_ingest_token", yaml: "envs:\n  prod: {ingest_token_env: LL_UNSET}\n", wantErr: "ingest token variable"},
		{name: "C4_rule_checks", yaml: minimal + `
rules:
  - {name: cpu, type: threshold, series: cpu.cpu_p, op: ">", value: "90", for: 5m}
  - {name: cpu, type: threshold, series: x, op: "~", value: "1"}
  - {name: st, type: text, series: backup.status, op: ">", value: ok}
  - {name: lr, type: lograte, pattern: "("}
  - {name: an, type: anomaly}
  - {name: Bad Name, type: nope}
`, wantErr: "duplicate"},
		{name: "C5_route_topic_missing", yaml: minimal + `
notifiers:
  tg: {telegram: {token_env: LL_TG, chat_id: "-1", topics: {alarms: 2}}}
routes:
  - {name: r, send: [tg/reports]}
`, wantErr: `tg has no target "reports"`},
		{name: "C6_ai_and_lightsail_need_secrets", yaml: minimal + `
ai: {model: m, key_env: LL_AI}
lightsail: {regions: [eu-central-1], access_key_env: LL_AK, secret_key_env: LL_SK}
`, env: map[string]string{"LL_AI": "k", "LL_AK": "a", "LL_SK": "s"}, check: func(t *testing.T, c *Config) {
			if !c.AIEnabled() || !c.LightsailEnabled() || c.Lightsail.Interval.D() != 15*time.Minute || c.AI.DailyCalls != 50 {
				t.Errorf("ai %v lightsail %v %+v", c.AIEnabled(), c.LightsailEnabled(), c.Lightsail)
			}
		}},
		{name: "C7_lightsail_without_credentials_is_off", yaml: minimal + `
lightsail: {regions: [eu-central-1], access_key_env: LL_AK2, secret_key_env: LL_SK2}
`, check: func(t *testing.T, c *Config) {
			if c.LightsailEnabled() {
				t.Error("poller enabled without credentials")
			}
		}},
		{name: "C8_report_route_and_time", yaml: minimal + "report: {at: '6am', route: nope}\n", wantErr: "report"},
		{name: "C9_auth_roles", yaml: minimal + `
auth:
  api_keys: [{name: d, key_env: LL_KEY, role: admin}]
  jwt: [{name: j, public_key_file: /x.pem, roles: {owner: [{claim: a, equals: true}]}}]
`, wantErr: `role "owner" must be one of`},
		{name: "C10_bad_duration", yaml: minimal + "tick: soon\n", wantErr: "invalid duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			c, err := Parse([]byte(tt.yaml))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}

func TestParseDurationDays(t *testing.T) {
	for in, want := range map[string]time.Duration{"5d": 120 * time.Hour, "90d": 90 * 24 * time.Hour, "36h": 36 * time.Hour, "15m": 15 * time.Minute} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"d", "-1d", "1.5d", "x"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestAgents(t *testing.T) {
	t.Setenv("LL_T", "t")
	base := "envs: {uat: {ingest_token_env: LL_T}}\nroutes: [{name: all, send: [hook]}]\nnotifiers: {hook: {webhook: {url_env: LL_T}}}\nai:\n  model: m\n"
	c, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	a := c.AI.Agents
	if len(a) != 1 || a[0].Name != "explain" || a[0].On != OnIncidentOpen || a[0].Model != "m" || a[0].Prompt != DefaultAgentPrompt ||
		a[0].MaxTokens != 400 || a[0].Context.Logs != 20 || a[0].Context.Level != "warning" || !*a[0].Context.Values {
		t.Fatalf("G6 default agent: %+v", a)
	}
	for name, yaml := range map[string]string{
		"both prompts":    "  agents: [{name: x, on: incident_open, prompt: a, prompt_file: b}]",
		"bad trigger":     "  agents: [{name: x, on: hourly}]",
		"unknown route":   "  agents: [{name: x, on: incident_open, route: nope}]",
		"match on report": "  agents: [{name: x, on: daily_report, match: {env: uat}}]",
		"missing file":    "  agents: [{name: x, on: incident_open, prompt_file: /nonexistent.md}]",
		"duplicate":       "  agents: [{name: x, on: incident_open}, {name: x, on: daily_report}]",
		"bad level":       "  agents: [{name: x, on: incident_open, context: {level: loud}}]",
		"unknown field":   "  agents: [{name: x, on: incident_open, tools: [shell]}]",
	} {
		if _, err := Parse([]byte(base + yaml)); err == nil {
			t.Errorf("G7 %s accepted", name)
		}
	}
	if _, err := Parse([]byte(strings.Replace(base, "  model: m\n", "  agents: [{name: x, on: incident_open}]\n", 1))); err == nil {
		t.Error("G7 agent without any model accepted")
	}
}

func TestNotifiers(t *testing.T) {
	t.Setenv("LL_T", "t")
	base := "envs: {uat: {ingest_token_env: LL_T}}\n"
	c, err := Parse([]byte(base + `
notifiers:
  tg:   {telegram: {token_env: LL_T, chat_id: "-1", topics: {ops: 2}}}
  sl:   {slack: {token_env: LL_T, channels: {ops: C1}}}
  hook: {slack: {webhook_url_env: LL_T}}
  mail: {email: {host: smtp.example.org, from: a@example.org, to: [b@example.org], targets: {mgmt: [c@example.org]}}}
  ssl:  {email: {host: smtp.example.org, port: 465, from: a@example.org, to: [b@example.org]}}
  wh:   {webhook: {url_env: LL_T}}
routes:
  - {name: r, send: [tg/ops, sl/ops, hook, mail/mgmt, ssl, wh/anything], digest: 1h, send_resolved: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	m := c.Notifiers["mail"].Email
	if m.Port != 587 || m.TLS != "starttls" || m.SubjectPrefix != "[loglantern]" || c.Notifiers["ssl"].Email.TLS != "tls" {
		t.Errorf("N11 email defaults: %+v %+v", m, c.Notifiers["ssl"].Email)
	}
	if r := c.Routes[0]; r.Resolved() || r.Digest.D() != time.Hour || c.Notifiers["sl"].Type() != "slack" {
		t.Errorf("N11 route: %+v", r)
	}
	if n, tgt := SplitDest("tg/ops/x"); n != "tg" || tgt != "ops/x" {
		t.Errorf("SplitDest: %s %s", n, tgt)
	}
	for name, y := range map[string]string{
		"two types":         "notifiers: {x: {webhook: {url_env: LL_T}, telegram: {token_env: LL_T, chat_id: '1'}}}",
		"no type":           "notifiers: {x: {}}",
		"unknown type":      "notifiers: {x: {discord: {url_env: LL_T}}}",
		"unknown notifier":  "routes: [{name: r, send: [nope]}]",
		"empty send":        "notifiers: {x: {webhook: {url_env: LL_T}}}\nroutes: [{name: r, send: []}]",
		"unknown topic":     "notifiers: {x: {telegram: {token_env: LL_T, chat_id: '1', topics: {a: 1}}}}\nroutes: [{name: r, send: [x/b]}]",
		"slack both":        "notifiers: {x: {slack: {token_env: LL_T, webhook_url_env: LL_T, channel: C}}}",
		"slack no channel":  "notifiers: {x: {slack: {token_env: LL_T}}}",
		"slack hook+chan":   "notifiers: {x: {slack: {webhook_url_env: LL_T, channel: C}}}",
		"slack hook target": "notifiers: {x: {slack: {webhook_url_env: LL_T}}}\nroutes: [{name: r, send: [x/ops]}]",
		"email no to":       "notifiers: {x: {email: {host: h, from: a@b.c}}}",
		"email bad tls":     "notifiers: {x: {email: {host: h, from: a@b.c, to: [d@e.f], tls: maybe}}}",
		"email half auth":   "notifiers: {x: {email: {host: h, from: a@b.c, to: [d@e.f], user_env: LL_T}}}",
		"bad name":          "notifiers: {Bad/Name: {webhook: {url_env: LL_T}}}",
		"old syntax":        "notifiers: {telegram: {token_env: LL_T, chat_id: '1'}}",
	} {
		if _, err := Parse([]byte(base + y)); err == nil {
			t.Errorf("N12 %s accepted", name)
		}
	}
}

func TestMaintenance(t *testing.T) {
	t.Setenv("LL_T", "t")
	c, err := Parse([]byte(`envs: {uat: {ingest_token_env: LL_T}}
maintenance:
  - {name: sunday-night, days: [sun], from: "23:00", to: "02:00", tz: Europe/Berlin}
  - {name: deploy, starts: 2026-10-05T10:00:00Z, ends: 2026-10-05T11:00:00Z, match: {host: h1}}
`))
	if err != nil {
		t.Fatal(err)
	}
	w, o := c.Maintenance[0], c.Maintenance[1]
	berlin, _ := time.LoadLocation("Europe/Berlin")
	for at, want := range map[time.Time]bool{
		time.Date(2026, 10, 4, 23, 30, 0, 0, berlin):   true,  // Sunday 23:30
		time.Date(2026, 10, 5, 1, 59, 0, 0, berlin):    true,  // Monday 01:59 belongs to Sunday's window
		time.Date(2026, 10, 5, 2, 0, 0, 0, berlin):     false, // end is exclusive
		time.Date(2026, 10, 5, 23, 30, 0, 0, berlin):   false, // Monday night
		time.Date(2026, 10, 4, 21, 30, 0, 0, time.UTC): true,  // = 23:30 Berlin (CEST)
	} {
		if got := w.Active(at); got != want {
			t.Errorf("W1 %s: %v", at, got)
		}
	}
	if !o.Active(time.Date(2026, 10, 5, 10, 30, 0, 0, time.UTC)) || o.Active(time.Date(2026, 10, 5, 11, 0, 0, 0, time.UTC)) {
		t.Error("W2 one-off")
	}
	for name, y := range map[string]string{
		"both kinds": "maintenance: [{from: '01:00', to: '02:00', starts: 2026-10-05T10:00:00Z, ends: 2026-10-05T11:00:00Z}]",
		"neither":    "maintenance: [{name: x}]",
		"bad day":    "maintenance: [{days: [funday], from: '01:00', to: '02:00'}]",
		"bad tz":     "maintenance: [{from: '01:00', to: '02:00', tz: Mars/Olympus}]",
		"same times": "maintenance: [{from: '01:00', to: '01:00'}]",
		"ends first": "maintenance: [{starts: 2026-10-05T11:00:00Z, ends: 2026-10-05T10:00:00Z}]",
		"bad role":   "auth: {api_keys: [{name: k, key_env: LL_T, role: root}]}",
	} {
		if _, err := Parse([]byte("envs: {uat: {ingest_token_env: LL_T}}\n" + y)); err == nil {
			t.Errorf("W3 %s accepted", name)
		}
	}
}
