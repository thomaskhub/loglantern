// Package config loads the loglantern configuration (YAML). Secrets are never in the file: the
// file names environment variables (…_env) that hold them.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/thomkin/loglantern/internal/record"
)

// Duration is a time.Duration written as "90s", "5m", "120h".
type Duration time.Duration

// UnmarshalYAML parses a Go duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// loadPrompts reads prompt_file of every agent into Prompt; agents without either get the default prompt.
func (c *Config) loadPrompts(dir string) error {
	if c.AI == nil {
		return nil
	}
	for i := range c.AI.Agents {
		a := &c.AI.Agents[i]
		switch {
		case a.Prompt != "" && a.PromptFile != "":
			return fmt.Errorf("ai.agents.%s: use prompt or prompt_file, not both", a.Name)
		case a.PromptFile != "":
			p := a.PromptFile
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("ai.agents.%s: %w", a.Name, err)
			}
			a.Prompt = strings.TrimSpace(string(b))
		case a.Prompt == "":
			a.Prompt = DefaultAgentPrompt
		}
		if strings.TrimSpace(a.Prompt) == "" {
			return fmt.Errorf("ai.agents.%s: prompt is empty", a.Name)
		}
	}
	return nil
}

// ParseDuration is time.ParseDuration plus whole days ("5d").
func ParseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n >= 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Config is the whole configuration.
type Config struct {
	Listen       Listen              `yaml:"listen"`
	Ingest       Ingest              `yaml:"ingest"`
	Storage      Storage             `yaml:"storage"`
	Envs         map[string]Env      `yaml:"envs"`
	Hosts        []Host              `yaml:"hosts"`
	MissingAfter Duration            `yaml:"missing_after"`
	Tick         Duration            `yaml:"tick"`
	Window       Duration            `yaml:"window"`
	Rules        []Rule              `yaml:"rules"`
	Routes       []Route             `yaml:"routes"`
	Notifiers    map[string]Notifier `yaml:"notifiers"`
	AI           *AI                 `yaml:"ai"`
	Probes       []Probe             `yaml:"probes"`
	Lightsail    *Lightsail          `yaml:"lightsail"`
	Report       *Report             `yaml:"report"`
	Maintenance  []Maintenance       `yaml:"maintenance"`
	Auth         Auth                `yaml:"auth"`
	CORS         []string            `yaml:"cors"`
	Secrets      map[string]string   `yaml:"-"` // resolved from the environment
}

// Listen addresses.
type Listen struct {
	Ingest string `yaml:"ingest"` // Fluent Bit (internal network)
	API    string `yaml:"api"`    // dashboards
}

// Ingest limits and privacy.
type Ingest struct {
	MaxBodyMB  int  `yaml:"max_body_mb"` // decompressed request size (default 16)
	MaskEmails bool `yaml:"mask_emails"` // replace e-mail addresses in messages
}

// Storage of the SQLite database.
type Storage struct {
	Path      string    `yaml:"path"`
	CacheMB   int       `yaml:"cache_mb"`
	Retention Retention `yaml:"retention"`
}

// Retention per kind of data.
type Retention struct {
	Logs      Duration `yaml:"logs"`
	Metrics   Duration `yaml:"metrics"`
	Counters  Duration `yaml:"counters"`
	Incidents Duration `yaml:"incidents"`
}

// Env is one environment (e.g. uat, prod) with its ingest token.
type Env struct {
	IngestTokenEnv string `yaml:"ingest_token_env"`
}

// Host is a known host: reported as missing even if it never sent anything.
type Host struct {
	Env  string `yaml:"env"`
	Host string `yaml:"host"`
	Role string `yaml:"role"`
}

// Match selects by labels; empty fields match everything.
type Match struct {
	Env      string   `yaml:"env"`
	Host     string   `yaml:"host"`
	Role     string   `yaml:"role"`
	Service  string   `yaml:"service"`
	Severity []string `yaml:"severity"`
}

// Fits reports whether the matcher accepts these labels (empty fields match everything).
func (m Match) Fits(env, host, role, service, severity string) bool {
	return (m.Env == "" || m.Env == env) && (m.Host == "" || m.Host == host) && (m.Role == "" || m.Role == role) &&
		(m.Service == "" || m.Service == service) && (len(m.Severity) == 0 || slices.Contains(m.Severity, severity))
}

// Rule types.
const (
	RuleThreshold = "threshold" // numeric series op value for a duration
	RuleText      = "text"      // text fact op value
	RuleLogRate   = "lograte"   // matching log lines per window >= count
	RuleAnomaly   = "anomaly"   // z-score against the series' own window
	RuleAbsent    = "absent"    // a series that was reported before has no value for max_age
)

// Severities, from low to high.
var Severities = []string{"info", "warning", "critical"}

// Rule is one alarm rule.
type Rule struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Series   string   `yaml:"series"` // metric or fact name, e.g. cpu.cpu_p, backup.age_h, backup.status
	Op       string   `yaml:"op"`     // > >= < <= == !=
	Value    string   `yaml:"value"`
	For      Duration `yaml:"for"`
	Severity string   `yaml:"severity"`
	Match    Match    `yaml:"match"`
	Text     string   `yaml:"text"` // message template: {rule} {env} {host} {value} {detail}
	// lograte
	Level   string   `yaml:"level"`   // minimum level: debug info notice warning error critical
	Pattern string   `yaml:"pattern"` // regular expression on the message
	Count   int      `yaml:"count"`
	Per     Duration `yaml:"per"`
	// anomaly
	ZScore     float64  `yaml:"zscore"`
	MinSamples int      `yaml:"min_samples"`
	MinDelta   float64  `yaml:"min_delta"`
	MaxAge     Duration `yaml:"max_age"` // absent
}

// Route sends matching incidents (and reports, AI answers) to one or more destinations.
type Route struct {
	Name         string   `yaml:"name"`
	Match        Match    `yaml:"match"`
	Send         []string `yaml:"send"`          // "notifier" or "notifier/target"
	Digest       Duration `yaml:"digest"`        // > 0: bundle messages, at most one delivery per period
	Repeat       Duration `yaml:"repeat"`        // > 0: remind about incidents still open after this long
	SendResolved *bool    `yaml:"send_resolved"` // default true
}

// Resolved reports whether resolved messages go to this route.
func (r Route) Resolved() bool { return r.SendResolved == nil || *r.SendResolved }

// SplitDest splits "notifier/target".
func SplitDest(d string) (notifier, target string) {
	notifier, target, _ = strings.Cut(d, "/")
	return notifier, target
}

// Notifier is one named output; exactly one type section is set.
// A new output type is a new section here plus its sender in package notify.
type Notifier struct {
	Telegram *Telegram `yaml:"telegram"`
	Slack    *Slack    `yaml:"slack"`
	Email    *Email    `yaml:"email"`
	Webhook  *Webhook  `yaml:"webhook"`
}

// Type returns the configured type ("" if none or several).
func (n Notifier) Type() string {
	var types []string
	if n.Telegram != nil {
		types = append(types, "telegram")
	}
	if n.Slack != nil {
		types = append(types, "slack")
	}
	if n.Email != nil {
		types = append(types, "email")
	}
	if n.Webhook != nil {
		types = append(types, "webhook")
	}
	if len(types) != 1 {
		return ""
	}
	return types[0]
}

// validTarget reports whether target is allowed ("" = the notifier's default).
func (n Notifier) validTarget(target string) bool {
	if target == "" {
		return true
	}
	switch {
	case n.Telegram != nil:
		_, ok := n.Telegram.Topics[target]
		return ok
	case n.Slack != nil:
		_, ok := n.Slack.Channels[target]
		return ok && n.Slack.TokenEnv != ""
	case n.Email != nil:
		_, ok := n.Email.Targets[target]
		return ok
	}
	return true // webhook: the target is passed on as a field
}

// Telegram bot; topics map a target name to a forum topic (message_thread_id).
type Telegram struct {
	TokenEnv string         `yaml:"token_env"`
	ChatID   string         `yaml:"chat_id"`
	Topics   map[string]int `yaml:"topics"`
	BaseURL  string         `yaml:"base_url"`
}

// Slack: a bot token (chat.postMessage; channels map a target to a channel id) or an incoming webhook (one channel).
type Slack struct {
	TokenEnv      string            `yaml:"token_env"`
	Channel       string            `yaml:"channel"`  // default channel id (bot token)
	Channels      map[string]string `yaml:"channels"` // target → channel id
	WebhookURLEnv string            `yaml:"webhook_url_env"`
	BaseURL       string            `yaml:"base_url"`
}

// Email over SMTP (works with most providers' SMTP relays).
type Email struct {
	Host          string              `yaml:"host"`
	Port          int                 `yaml:"port"` // default 587
	TLS           string              `yaml:"tls"`  // starttls (default), tls (implicit, port 465) or none
	UserEnv       string              `yaml:"user_env"`
	PasswordEnv   string              `yaml:"password_env"`
	From          string              `yaml:"from"`
	To            []string            `yaml:"to"`      // default recipients
	Targets       map[string][]string `yaml:"targets"` // target → recipients
	SubjectPrefix string              `yaml:"subject_prefix"`
}

// Webhook posts {"text", "target"} to a URL held in an environment variable.
type Webhook struct {
	URLEnv string `yaml:"url_env"`
}

// AI enrichment (OpenAI-compatible chat completions, e.g. OpenRouter). Enabled when present.
type AI struct {
	BaseURL    string         `yaml:"base_url"`
	Model      string         `yaml:"model"`
	KeyEnv     string         `yaml:"key_env"`
	DailyCalls int            `yaml:"daily_calls"`
	MaxTokens  int            `yaml:"max_tokens"`
	Timeout    Duration       `yaml:"timeout"`
	Extra      map[string]any `yaml:"extra"` // merged into the request, e.g. reasoning: {effort: none}
	Agents     []Agent        `yaml:"agents"`
}

// AI agent triggers.
const (
	OnIncidentOpen = "incident_open" // context: alert, last values, recent log lines of the host
	OnDailyReport  = "daily_report"  // context: the daily report text
)

// DefaultAgentPrompt is used by agents without prompt or prompt_file.
const DefaultAgentPrompt = `You help an operator understand a server alert. Answer in at most 3 short sentences of plain text: ` +
	`the likely cause and the first thing to check. Do not repeat the alert. If the context is not enough, say so briefly.`

// Agent is one AI step: when it runs, which model, which instructions and how much context it gets.
// It makes one call without tools; its answer is only sent as a message, never used to decide alarms.
type Agent struct {
	Name       string         `yaml:"name"`
	On         string         `yaml:"on"`    // incident_open | daily_report
	Match      Match          `yaml:"match"` // incident_open only
	Model      string         `yaml:"model"` // default ai.model
	MaxTokens  int            `yaml:"max_tokens"`
	Prompt     string         `yaml:"prompt"`      // inline system prompt
	PromptFile string         `yaml:"prompt_file"` // or a file (relative to the config file)
	Context    AgentContext   `yaml:"context"`
	Route      string         `yaml:"route"` // "" = the incident's routes (or the report route)
	Extra      map[string]any `yaml:"extra"` // merged over ai.extra
}

// AgentContext limits what an incident agent sees.
type AgentContext struct {
	Logs     int      `yaml:"logs"`     // recent log lines of the host (default 20, -1 = none)
	Level    string   `yaml:"level"`    // this level or worse (default warning)
	Lookback Duration `yaml:"lookback"` // before the incident (default 30m)
	Values   *bool    `yaml:"values"`   // last values of the host (default true)
}

// Probe is an HTTP check; results become the series probe.up and probe.latency_ms.
type Probe struct {
	Name         string   `yaml:"name"`
	Env          string   `yaml:"env"`
	Host         string   `yaml:"host"`
	URL          string   `yaml:"url"`
	Interval     Duration `yaml:"interval"`
	Timeout      Duration `yaml:"timeout"`
	ExpectStatus int      `yaml:"expect_status"`
	Contains     string   `yaml:"contains"`
}

// Lightsail credits poller; active only when the credential variables are set.
type Lightsail struct {
	Regions      []string                    `yaml:"regions"`
	AccessKeyEnv string                      `yaml:"access_key_env"`
	SecretKeyEnv string                      `yaml:"secret_key_env"`
	Interval     Duration                    `yaml:"interval"`
	Instances    map[string]LightsailMapping `yaml:"instances"` // instance name → env/host
	Endpoint     string                      `yaml:"endpoint"`  // tests only
}

// LightsailMapping maps an instance to env and host.
type LightsailMapping struct {
	Env  string `yaml:"env"`
	Host string `yaml:"host"`
}

// Maintenance silences notifications in a weekly window or a one-off period; incidents are still recorded.
type Maintenance struct {
	Name   string    `yaml:"name"`
	Match  Match     `yaml:"match"`
	Rule   string    `yaml:"rule"`   // only this rule ("" = all)
	Days   []string  `yaml:"days"`   // weekly: mon … sun (empty = every day)
	From   string    `yaml:"from"`   // weekly: "HH:MM"
	To     string    `yaml:"to"`     // weekly: "HH:MM" (may be past midnight)
	TZ     string    `yaml:"tz"`     // weekly: IANA zone (default UTC)
	Starts time.Time `yaml:"starts"` // one-off (RFC 3339)
	Ends   time.Time `yaml:"ends"`
	loc    *time.Location
}

var weekdays = map[string]time.Weekday{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

// Active reports whether the window covers t.
func (m Maintenance) Active(t time.Time) bool {
	if !m.Ends.IsZero() {
		return !t.Before(m.Starts) && t.Before(m.Ends)
	}
	loc := m.loc
	if loc == nil {
		loc = time.UTC
	}
	lt := t.In(loc)
	from, _ := time.Parse("15:04", m.From)
	to, _ := time.Parse("15:04", m.To)
	mins := lt.Hour()*60 + lt.Minute()
	f, e := from.Hour()*60+from.Minute(), to.Hour()*60+to.Minute()
	day := lt.Weekday()
	if f > e && mins < e { // window past midnight: the early part belongs to the previous day
		day = (day + 6) % 7
	}
	if len(m.Days) > 0 && !slices.ContainsFunc(m.Days, func(d string) bool { return weekdays[strings.ToLower(d)] == day }) {
		return false
	}
	if f <= e {
		return mins >= f && mins < e
	}
	return mins >= f || mins < e
}

// Report is the daily summary.
type Report struct {
	At    string `yaml:"at"`    // "06:00" UTC
	Route string `yaml:"route"` // route name
}

// Auth for the API.
type Auth struct {
	APIKeys []APIKey `yaml:"api_keys"`
	JWT     []JWTKey `yaml:"jwt"`
}

// Roles: viewer sees status, incidents and charts; logs additionally sees log lines;
// admin additionally manages silences.
const (
	RoleViewer = "viewer"
	RoleLogs   = "logs"
	RoleAdmin  = "admin"
)

// Roles from high to low.
var Roles = []string{RoleAdmin, RoleLogs, RoleViewer}

// APIKey is a static bearer key (e.g. for a server-side dashboard).
type APIKey struct {
	Name   string   `yaml:"name"`
	KeyEnv string   `yaml:"key_env"`
	Role   string   `yaml:"role"`
	Envs   []string `yaml:"envs"`
}

// JWTKey verifies tokens of one issuer (RS256, ES256 or EdDSA public key in PEM).
type JWTKey struct {
	Name          string                  `yaml:"name"`
	PublicKeyFile string                  `yaml:"public_key_file"`
	Envs          []string                `yaml:"envs"`  // environments tokens of this key may see
	Roles         map[string][]ClaimMatch `yaml:"roles"` // role → any of these claims
}

// ClaimMatch matches a claim path (dot separated) against a value.
type ClaimMatch struct {
	Claim  string `yaml:"claim"`
	Equals any    `yaml:"equals"`
}

var (
	nameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,40}$`)
	ops    = []string{">", ">=", "<", "<=", "==", "!="}
)

// Load reads, defaults and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parse(b, filepath.Dir(path))
}

// Parse parses YAML, applies defaults, resolves secrets and validates; prompt files are relative to the working directory.
func Parse(b []byte) (*Config, error) { return parse(b, ".") }

func parse(b []byte, dir string) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.defaults()
	c.resolveSecrets()
	if err := c.loadPrompts(dir); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) defaults() {
	def := func(d *Duration, v time.Duration) {
		if *d == 0 {
			*d = Duration(v)
		}
	}
	for _, n := range c.Notifiers {
		if e := n.Email; e != nil {
			if e.Port == 0 {
				e.Port = 587
				if e.TLS == "tls" {
					e.Port = 465
				}
			}
			if e.TLS == "" {
				e.TLS = "starttls"
				if e.Port == 465 {
					e.TLS = "tls"
				}
			}
			if e.SubjectPrefix == "" {
				e.SubjectPrefix = "[loglantern]"
			}
		}
	}
	if c.Ingest.MaxBodyMB == 0 {
		c.Ingest.MaxBodyMB = 16
	}
	if c.Listen.Ingest == "" {
		c.Listen.Ingest = "127.0.0.1:8440"
	}
	if c.Listen.API == "" {
		c.Listen.API = "127.0.0.1:8441"
	}
	if c.Storage.Path == "" {
		c.Storage.Path = "loglantern.db"
	}
	if c.Storage.CacheMB == 0 {
		c.Storage.CacheMB = 32
	}
	r := &c.Storage.Retention
	def(&r.Logs, 5*24*time.Hour)
	def(&r.Metrics, 5*24*time.Hour)
	def(&r.Counters, 90*24*time.Hour)
	def(&r.Incidents, 90*24*time.Hour)
	def(&c.MissingAfter, 3*time.Minute)
	def(&c.Tick, 15*time.Second)
	def(&c.Window, 2*time.Hour)
	for i := range c.Rules {
		ru := &c.Rules[i]
		if ru.Severity == "" {
			ru.Severity = "warning"
		}
		if ru.Type == RuleLogRate && ru.Per == 0 {
			ru.Per = Duration(5 * time.Minute)
		}
		if ru.Type == RuleAnomaly {
			if ru.ZScore == 0 {
				ru.ZScore = 4
			}
			if ru.MinSamples == 0 {
				ru.MinSamples = 30
			}
		}
	}
	for i := range c.Probes {
		p := &c.Probes[i]
		def(&p.Interval, 5*time.Minute)
		def(&p.Timeout, 10*time.Second)
		if p.ExpectStatus == 0 {
			p.ExpectStatus = 200
		}
	}
	if c.AI != nil {
		if c.AI.BaseURL == "" {
			c.AI.BaseURL = "https://openrouter.ai/api/v1"
		}
		if c.AI.DailyCalls == 0 {
			c.AI.DailyCalls = 50
		}
		if c.AI.MaxTokens == 0 {
			c.AI.MaxTokens = 400
		}
		def(&c.AI.Timeout, 60*time.Second)
		if len(c.AI.Agents) == 0 {
			c.AI.Agents = []Agent{{Name: "explain", On: OnIncidentOpen}}
		}
		for i := range c.AI.Agents {
			a := &c.AI.Agents[i]
			if a.Model == "" {
				a.Model = c.AI.Model
			}
			if a.MaxTokens == 0 {
				a.MaxTokens = c.AI.MaxTokens
			}
			if a.Context.Logs == 0 {
				a.Context.Logs = 20
			}
			if a.Context.Level == "" {
				a.Context.Level = "warning"
			}
			def(&a.Context.Lookback, 30*time.Minute)
			if a.Context.Values == nil {
				t := true
				a.Context.Values = &t
			}
		}
	}
	if c.Lightsail != nil {
		def(&c.Lightsail.Interval, 15*time.Minute)
	}
}

// resolveSecrets reads every *_env variable named in the config.
func (c *Config) resolveSecrets() {
	c.Secrets = map[string]string{}
	add := func(name string) {
		if name != "" {
			c.Secrets[name] = os.Getenv(name)
		}
	}
	for _, e := range c.Envs {
		add(e.IngestTokenEnv)
	}
	for _, n := range c.Notifiers {
		switch {
		case n.Telegram != nil:
			add(n.Telegram.TokenEnv)
		case n.Slack != nil:
			add(n.Slack.TokenEnv)
			add(n.Slack.WebhookURLEnv)
		case n.Email != nil:
			add(n.Email.UserEnv)
			add(n.Email.PasswordEnv)
		case n.Webhook != nil:
			add(n.Webhook.URLEnv)
		}
	}
	if c.AI != nil {
		add(c.AI.KeyEnv)
	}
	if l := c.Lightsail; l != nil {
		add(l.AccessKeyEnv)
		add(l.SecretKeyEnv)
	}
	for _, k := range c.Auth.APIKeys {
		add(k.KeyEnv)
	}
}

// Secret returns the value of a secret variable named in the config.
func (c *Config) Secret(name string) string { return c.Secrets[name] }

// LightsailEnabled reports whether the poller has credentials.
func (c *Config) LightsailEnabled() bool {
	l := c.Lightsail
	return l != nil && c.Secret(l.AccessKeyEnv) != "" && c.Secret(l.SecretKeyEnv) != ""
}

// AIEnabled reports whether AI enrichment is configured with a key.
func (c *Config) AIEnabled() bool { return c.AI != nil && c.Secret(c.AI.KeyEnv) != "" }

func (c *Config) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if len(c.Envs) == 0 {
		bad("envs: at least one environment is required")
	}
	for name, e := range c.Envs {
		if !nameRe.MatchString(name) {
			bad("envs.%s: invalid name", name)
		}
		if c.Secret(e.IngestTokenEnv) == "" {
			bad("envs.%s: ingest token variable %q is empty", name, e.IngestTokenEnv)
		}
	}
	hasEnv := func(e string) bool { _, ok := c.Envs[e]; return ok }
	for i, h := range c.Hosts {
		if !hasEnv(h.Env) || h.Host == "" {
			bad("hosts[%d]: env must be a configured environment and host must be set", i)
		}
	}
	routes := map[string]bool{}
	for i, r := range c.Routes {
		if r.Name == "" || routes[r.Name] {
			bad("routes[%d]: name missing or duplicate", i)
		}
		routes[r.Name] = true
		if len(r.Send) == 0 {
			bad("routes.%s: send needs at least one notifier", r.Name)
		}
		for _, d := range r.Send {
			name, target := SplitDest(d)
			n, ok := c.Notifiers[name]
			switch {
			case !ok:
				bad("routes.%s: notifier %q is not configured", r.Name, name)
			case !n.validTarget(target):
				bad("routes.%s: %s has no target %q", r.Name, name, target)
			}
		}
		if r.Digest < 0 {
			bad("routes.%s: digest must not be negative", r.Name)
		}
	}
	for name, n := range c.Notifiers {
		if !nameRe.MatchString(name) {
			bad("notifiers.%s: invalid name", name)
		}
		switch n.Type() {
		case "telegram":
			if n.Telegram.TokenEnv == "" || n.Telegram.ChatID == "" {
				bad("notifiers.%s: telegram needs token_env and chat_id", name)
			}
		case "slack":
			sl := n.Slack
			if (sl.TokenEnv == "") == (sl.WebhookURLEnv == "") {
				bad("notifiers.%s: slack needs token_env or webhook_url_env (one of them)", name)
			}
			if sl.TokenEnv != "" && sl.Channel == "" && len(sl.Channels) == 0 {
				bad("notifiers.%s: slack with token_env needs channel or channels", name)
			}
			if sl.WebhookURLEnv != "" && (sl.Channel != "" || len(sl.Channels) > 0) {
				bad("notifiers.%s: a slack webhook posts to its own channel; remove channel(s)", name)
			}
		case "email":
			e := n.Email
			if e.Host == "" || e.From == "" || (len(e.To) == 0 && len(e.Targets) == 0) {
				bad("notifiers.%s: email needs host, from and to (or targets)", name)
			}
			if !slices.Contains([]string{"starttls", "tls", "none"}, e.TLS) {
				bad("notifiers.%s: email tls must be starttls, tls or none", name)
			}
			if (e.UserEnv == "") != (e.PasswordEnv == "") {
				bad("notifiers.%s: email needs both user_env and password_env, or neither", name)
			}
		case "webhook":
			if n.Webhook.URLEnv == "" {
				bad("notifiers.%s: webhook needs url_env", name)
			}
		default:
			bad("notifiers.%s: set exactly one of telegram, slack, email, webhook", name)
		}
	}
	names := map[string]bool{}
	for i, r := range c.Rules {
		if !nameRe.MatchString(r.Name) || names[r.Name] {
			bad("rules[%d]: name %q missing, invalid or duplicate", i, r.Name)
		}
		names[r.Name] = true
		if !slices.Contains(Severities, r.Severity) {
			bad("rules.%s: severity must be one of %v", r.Name, Severities)
		}
		switch r.Type {
		case RuleThreshold, RuleText:
			if r.Series == "" || !slices.Contains(ops, r.Op) || r.Value == "" {
				bad("rules.%s: needs series, op (%v) and value", r.Name, ops)
			}
			if r.Type == RuleText && r.Op != "==" && r.Op != "!=" {
				bad("rules.%s: text rules support == and != only", r.Name)
			}
		case RuleLogRate:
			if r.Count <= 0 {
				bad("rules.%s: lograte needs count > 0", r.Name)
			}
			if r.Pattern != "" {
				if _, err := regexp.Compile(r.Pattern); err != nil {
					bad("rules.%s: pattern: %v", r.Name, err)
				}
			}
		case RuleAnomaly:
			if r.Series == "" {
				bad("rules.%s: anomaly needs series", r.Name)
			}
		case RuleAbsent:
			if r.Series == "" || r.MaxAge <= 0 {
				bad("rules.%s: absent needs series and max_age", r.Name)
			}
		default:
			bad("rules.%s: type must be threshold, text, lograte, anomaly or absent", r.Name)
		}
	}
	for i, p := range c.Probes {
		if p.Name == "" || p.URL == "" || !hasEnv(p.Env) {
			bad("probes[%d]: name, url and a configured env are required", i)
		}
	}
	if c.AI != nil {
		names := map[string]bool{}
		for i, a := range c.AI.Agents {
			if !nameRe.MatchString(a.Name) || names[a.Name] {
				bad("ai.agents[%d]: name missing, invalid or duplicate", i)
			}
			names[a.Name] = true
			if a.On != OnIncidentOpen && a.On != OnDailyReport {
				bad("ai.agents.%s: on must be %s or %s", a.Name, OnIncidentOpen, OnDailyReport)
			}
			if a.Model == "" {
				bad("ai.agents.%s: model is required (or set ai.model)", a.Name)
			}
			if a.Route != "" && !routes[a.Route] {
				bad("ai.agents.%s: route %q is not configured", a.Name, a.Route)
			}
			if _, ok := record.ParseLevel(a.Context.Level); !ok {
				bad("ai.agents.%s: context.level %q unknown", a.Name, a.Context.Level)
			}
			if a.On == OnDailyReport && (a.Match.Env != "" || a.Match.Host != "" || a.Match.Role != "" || a.Match.Service != "" || len(a.Match.Severity) > 0) {
				bad("ai.agents.%s: match only applies to %s", a.Name, OnIncidentOpen)
			}
		}
	}
	if c.Report != nil && !routes[c.Report.Route] {
		bad("report: route %q is not configured", c.Report.Route)
	}
	if c.Report != nil {
		if _, err := time.Parse("15:04", c.Report.At); err != nil {
			bad("report.at: want HH:MM (UTC)")
		}
	}
	for i := range c.Maintenance {
		m := &c.Maintenance[i]
		label := fmt.Sprintf("maintenance[%d]", i)
		if m.Name != "" {
			label = "maintenance." + m.Name
		}
		oneOff := !m.Starts.IsZero() || !m.Ends.IsZero()
		weekly := m.From != "" || m.To != "" || len(m.Days) > 0
		switch {
		case oneOff == weekly:
			bad("%s: set either from/to (weekly) or starts/ends (one-off)", label)
		case oneOff && !m.Ends.After(m.Starts):
			bad("%s: ends must be after starts", label)
		case weekly:
			_, e1 := time.Parse("15:04", m.From)
			_, e2 := time.Parse("15:04", m.To)
			if e1 != nil || e2 != nil || m.From == m.To {
				bad("%s: from and to must be different HH:MM", label)
			}
			for _, d := range m.Days {
				if _, ok := weekdays[strings.ToLower(d)]; !ok {
					bad("%s: unknown day %q", label, d)
				}
			}
			tz := m.TZ
			if tz == "" {
				tz = "UTC"
			}
			loc, err := time.LoadLocation(tz)
			if err != nil {
				bad("%s: tz: %v", label, err)
			}
			m.loc = loc
		}
	}
	for i, k := range c.Auth.APIKeys {
		if !slices.Contains(Roles, k.Role) {
			bad("auth.api_keys[%d]: role must be one of %v", i, Roles)
		}
		if c.Secret(k.KeyEnv) == "" {
			bad("auth.api_keys[%d]: key variable %q is empty", i, k.KeyEnv)
		}
	}
	for i, j := range c.Auth.JWT {
		if j.PublicKeyFile == "" || len(j.Roles) == 0 {
			bad("auth.jwt[%d]: public_key_file and roles are required", i)
		}
		for role := range j.Roles {
			if !slices.Contains(Roles, role) {
				bad("auth.jwt[%d]: role %q must be one of %v", i, role, Roles)
			}
		}
	}
	return errors.Join(errs...)
}
