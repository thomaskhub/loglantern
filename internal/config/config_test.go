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
  telegram: {token_env: LL_TG, chat_id: "-1", topics: {alarms: 2}}
routes:
  - {name: r, notifier: telegram, target: reports}
`, wantErr: `topic "reports"`},
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
`, wantErr: "role must be viewer or logs"},
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
