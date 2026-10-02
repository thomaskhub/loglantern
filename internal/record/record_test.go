package record

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func parse(t *testing.T, js string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNormalize(t *testing.T) {
	o := Options{MaskEmails: true}
	tests := []struct {
		name    string
		in      string
		wantErr string
		check   func(t *testing.T, r Record)
	}{
		{name: "R1_journald_line", in: `{"date":1790935501.25,"host":"api-in","role":"api","MESSAGE":"\u001b[31merror\u001b[39m: db down for a@b.org","PRIORITY":"3","SYSLOG_IDENTIFIER":"shop-api","_PID":"12"}`,
			check: func(t *testing.T, r Record) {
				if r.Kind != KindLog || r.Level != LevelError || r.Service != "shop-api" || r.Role != "api" {
					t.Errorf("%+v", r)
				}
				if r.Message != "error: db down for <email>" {
					t.Errorf("message %q (ANSI + email)", r.Message)
				}
				if r.TS.Unix() != 1790935501 || r.TS.Nanosecond() != 250000000 {
					t.Errorf("ts %v", r.TS)
				}
				if _, ok := r.Fields["_PID"]; ok {
					t.Error("journald internals kept")
				}
			}},
		{name: "R2_json_app_line", in: `{"host":"api-in","MESSAGE":"{\"level\":\"warn\",\"msg\":\"slow query\",\"service\":\"api\",\"duration_ms\":812,\"request_id\":\"r1\"}","SYSLOG_IDENTIFIER":"bun"}`,
			check: func(t *testing.T, r Record) {
				if r.Level != LevelWarning || r.Message != "slow query" || r.Service != "api" || r.Fields["duration_ms"] != 812.0 || r.Fields["request_id"] != "r1" {
					t.Errorf("%+v", r)
				}
			}},
		{name: "R3_fact_via_journald", in: `{"host":"db1","SYSLOG_IDENTIFIER":"loglantern-fact","MESSAGE":"{\"fact\":\"backup\",\"age_h\":7.5,\"status\":\"ok\",\"verified\":true}"}`,
			check: func(t *testing.T, r Record) {
				if r.Kind != KindFact || r.Values["backup.age_h"] != 7.5 || r.Texts["backup.status"] != "ok" || r.Texts["backup.verified"] != "true" {
					t.Errorf("%+v", r)
				}
			}},
		{name: "R4_fact_record", in: `{"host":"db1","kind":"fact","fact":"repl","lag_s":3}`,
			check: func(t *testing.T, r Record) {
				if r.Values["repl.lag_s"] != 3 {
					t.Errorf("%+v", r)
				}
			}},
		{name: "R5_cpu_metric", in: `{"date":"2026-10-02T11:59:00.000Z","host":"api-in","kind":"metric","source":"cpu","cpu_p":12.5,"user_p":10,"cpu0.p_cpu":3,"note":"x"}`,
			check: func(t *testing.T, r Record) {
				if r.Values["cpu.cpu_p"] != 12.5 || r.Values["cpu.cpu0.p_cpu"] != 3 || len(r.Values) != 3 || r.TS.Minute() != 59 {
					t.Errorf("%+v", r)
				}
			}},
		{name: "R6_no_host", in: `{"MESSAGE":"x"}`, wantErr: "without host"},
		{name: "R7_unknown_kind", in: `{"host":"h","kind":"trace"}`, wantErr: "unknown kind"},
		{name: "R8_metric_without_numbers", in: `{"host":"h","kind":"metric","source":"mem","x":"y"}`, wantErr: "without numeric"},
		{name: "R9_fact_not_json", in: `{"host":"h","SYSLOG_IDENTIFIER":"loglantern-fact","MESSAGE":"backup ok"}`, wantErr: "not a JSON object"},
		{name: "R10_no_date_uses_now_and_default_level", in: `{"host":"h","log":"plain"}`,
			check: func(t *testing.T, r Record) {
				if !r.TS.Equal(now) || r.Level != LevelInfo || r.Message != "plain" {
					t.Errorf("%+v", r)
				}
			}},
		{name: "R11_long_message_cut", in: `{"host":"h","MESSAGE":"` + strings.Repeat("x", 9000) + `"}`,
			check: func(t *testing.T, r Record) {
				if len(r.Message) != 8<<10+len("…") {
					t.Errorf("len %d", len(r.Message))
				}
			}},
		{name: "R12_unit_as_service", in: `{"host":"h","MESSAGE":"m","_SYSTEMD_UNIT":"cron.service"}`,
			check: func(t *testing.T, r Record) {
				if r.Service != "cron" {
					t.Errorf("service %q", r.Service)
				}
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Normalize(parse(t, tt.in), "uat", now, o)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Env != "uat" {
				t.Errorf("env %q", r.Env)
			}
			tt.check(t, r)
		})
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]int{"error": 3, "WARN": 4, "7": 7, " info ": 6, "fatal": 1} {
		if got, ok := ParseLevel(in); !ok || got != want {
			t.Errorf("%q → %d %v", in, got, ok)
		}
	}
	if _, ok := ParseLevel("loud"); ok {
		t.Error("unknown level accepted")
	}
}
