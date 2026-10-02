// Package record turns the JSON records Fluent Bit sends (http output, format json) into one
// normalised Record: a log line, a set of metric values or a check fact.
//
// Conventions (see README): Fluent Bit adds host, role and kind ("log" default, "metric", "fact");
// metric records carry "source" (e.g. cpu, mem) and numeric fields; facts are JSON objects with a
// "fact" name, either as the record itself or as the MESSAGE of a journald line from the
// identifier "loglantern-fact".
package record

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Kinds of records.
const (
	KindLog    = "log"
	KindMetric = "metric"
	KindFact   = "fact"
)

// FactIdentifier is the journald SYSLOG_IDENTIFIER whose messages are facts.
const FactIdentifier = "loglantern-fact"

// Syslog levels.
const (
	LevelCritical = 2
	LevelError    = 3
	LevelWarning  = 4
	LevelNotice   = 5
	LevelInfo     = 6
	LevelDebug    = 7
)

var levelNames = map[string]int{
	"emerg": 0, "emergency": 0, "panic": 0, "fatal": 1, "alert": 1, "crit": 2, "critical": 2,
	"err": 3, "error": 3, "warn": 4, "warning": 4, "notice": 5, "info": 6, "information": 6, "debug": 7, "trace": 7,
}

// LevelNames maps a level to its canonical name.
var LevelNames = []string{"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}

// ParseLevel accepts a name ("error", "warn", …) or a syslog number; ok=false when unknown.
func ParseLevel(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 7 {
		return n, true
	}
	n, ok := levelNames[s]
	return n, ok
}

// Record is one normalised record.
type Record struct {
	Kind    string
	TS      time.Time
	Env     string
	Host    string
	IP      string
	Role    string
	Service string
	Level   int
	Message string
	Fields  map[string]any     // remaining fields of a log line
	Values  map[string]float64 // metric/fact numeric series (name → value)
	Texts   map[string]string  // fact text series (name → value)
	// Synthetic records come from loglantern itself (probes, Lightsail); they do not count as a heartbeat.
	Synthetic bool
}

// Options of the normaliser.
type Options struct {
	MaskEmails bool
	MaxMessage int // bytes; longer messages are cut (default 8 KiB)
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	ansiRe  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	// label and bookkeeping fields that are never values or log fields
	reserved = map[string]bool{
		"date": true, "host": true, "hostname": true, "_HOSTNAME": true, "role": true, "env": true,
		"kind": true, "source": true, "ip": true, "service": true,
	}
)

const defaultMaxMessage = 8 << 10

// Normalize converts one Fluent Bit record of the given environment (from the ingest token).
func Normalize(raw map[string]any, env string, now time.Time, o Options) (Record, error) {
	r := Record{Env: env, TS: timestamp(raw["date"], now), Kind: str(raw["kind"])}
	r.Host = firstStr(raw, "host", "hostname", "_HOSTNAME")
	r.Role, r.IP = str(raw["role"]), str(raw["ip"])
	if r.Host == "" {
		return r, errors.New("record without host")
	}
	if r.Kind == "" {
		r.Kind = KindLog
	}
	switch r.Kind {
	case KindMetric:
		return metric(r, raw)
	case KindFact:
		return fact(r, raw)
	case KindLog:
		if str(raw["SYSLOG_IDENTIFIER"]) == FactIdentifier {
			var obj map[string]any
			if json.Unmarshal([]byte(str(raw["MESSAGE"])), &obj) != nil {
				return r, errors.New("fact line is not a JSON object")
			}
			r.Kind = KindFact
			return fact(r, obj)
		}
		return logLine(r, raw, o), nil
	}
	return r, fmt.Errorf("unknown kind %q", r.Kind)
}

func metric(r Record, raw map[string]any) (Record, error) {
	src := str(raw["source"])
	if src == "" {
		src = "metric"
	}
	r.Service = src
	r.Values = map[string]float64{}
	for k, v := range raw {
		if reserved[k] {
			continue
		}
		if f, ok := number(v); ok {
			r.Values[src+"."+k] = f
		}
	}
	if len(r.Values) == 0 {
		return r, errors.New("metric record without numeric fields")
	}
	return r, nil
}

func fact(r Record, obj map[string]any) (Record, error) {
	name := str(obj["fact"])
	if name == "" {
		return r, errors.New(`fact without "fact" name`)
	}
	r.Service = name
	r.Values, r.Texts = map[string]float64{}, map[string]string{}
	for k, v := range obj {
		if k == "fact" || reserved[k] {
			continue
		}
		if f, ok := number(v); ok {
			r.Values[name+"."+k] = f
		} else if s, ok := v.(string); ok {
			r.Texts[name+"."+k] = s
		} else if b, ok := v.(bool); ok {
			r.Texts[name+"."+k] = strconv.FormatBool(b)
		}
	}
	return r, nil
}

func logLine(r Record, raw map[string]any, o Options) Record {
	r.Level = LevelInfo
	if p, ok := ParseLevel(str(raw["PRIORITY"])); ok {
		r.Level = p
	}
	if l, ok := ParseLevel(str(raw["level"])); ok {
		r.Level = l
	}
	r.Service = firstStr(raw, "service", "SYSLOG_IDENTIFIER")
	if r.Service == "" {
		r.Service = strings.TrimSuffix(str(raw["_SYSTEMD_UNIT"]), ".service")
	}
	r.Message = firstStr(raw, "MESSAGE", "message", "msg", "log")
	r.Fields = map[string]any{}
	// application logs written as one JSON object per line
	if strings.HasPrefix(strings.TrimSpace(r.Message), "{") {
		var obj map[string]any
		if json.Unmarshal([]byte(r.Message), &obj) == nil {
			if l, ok := ParseLevel(str(obj["level"])); ok {
				r.Level = l
			}
			if s := firstStr(obj, "service"); s != "" {
				r.Service = s
			}
			r.Message = firstStr(obj, "msg", "message")
			for k, v := range obj {
				if k != "level" && k != "msg" && k != "message" && k != "service" {
					r.Fields[k] = v
				}
			}
		}
	}
	for k, v := range raw {
		if !reserved[k] && k != "MESSAGE" && k != "message" && k != "msg" && k != "log" && k != "PRIORITY" && k != "level" && !strings.HasPrefix(k, "_") && k != "SYSLOG_IDENTIFIER" && k != "SYSLOG_FACILITY" && k != "SYSLOG_TIMESTAMP" && k != "SYSLOG_PID" {
			r.Fields[k] = v
		}
	}
	r.Message = ansiRe.ReplaceAllString(r.Message, "")
	if o.MaskEmails {
		r.Message = emailRe.ReplaceAllString(r.Message, "<email>")
	}
	max := o.MaxMessage
	if max <= 0 {
		max = defaultMaxMessage
	}
	if len(r.Message) > max {
		r.Message = r.Message[:max] + "…"
	}
	return r
}

func timestamp(v any, now time.Time) time.Time {
	switch d := v.(type) {
	case float64:
		sec, frac := math.Modf(d)
		return time.Unix(int64(sec), int64(frac*1e9)).UTC()
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999Z0700", "2006-01-02 15:04:05.999999999"} {
			if t, err := time.Parse(layout, d); err == nil {
				return t.UTC()
			}
		}
	}
	return now.UTC()
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func str(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := str(m[k]); s != "" {
			return s
		}
	}
	return ""
}
