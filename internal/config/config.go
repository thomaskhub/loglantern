// Package config loads the loglantern configuration (YAML). Secrets are never in the file: the
// file names environment variables (…_env) that hold them.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	Listen       Listen            `yaml:"listen"`
	Ingest       Ingest            `yaml:"ingest"`
	Storage      Storage           `yaml:"storage"`
	Envs         map[string]Env    `yaml:"envs"`
	Hosts        []Host            `yaml:"hosts"`
	MissingAfter Duration          `yaml:"missing_after"`
	Tick         Duration          `yaml:"tick"`
	Window       Duration          `yaml:"window"`
	Rules        []Rule            `yaml:"rules"`
	Routes       []Route           `yaml:"routes"`
	Notifiers    Notifiers         `yaml:"notifiers"`
	AI           *AI               `yaml:"ai"`
	Probes       []Probe           `yaml:"probes"`
	Lightsail    *Lightsail        `yaml:"lightsail"`
	Report       *Report           `yaml:"report"`
	Auth         Auth              `yaml:"auth"`
	CORS         []string          `yaml:"cors"`
	Secrets      map[string]string `yaml:"-"` // resolved from the environment
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

// Rule types.
const (
	RuleThreshold = "threshold" // numeric series op value for a duration
	RuleText      = "text"      // text fact op value
	RuleLogRate   = "lograte"   // matching log lines per window >= count
	RuleAnomaly   = "anomaly"   // z-score against the series' own window
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
	ZScore     float64 `yaml:"zscore"`
	MinSamples int     `yaml:"min_samples"`
	MinDelta   float64 `yaml:"min_delta"`
}

// Route sends matching incidents (and reports) to a notifier target.
type Route struct {
	Name     string `yaml:"name"`
	Match    Match  `yaml:"match"`
	Notifier string `yaml:"notifier"` // telegram | webhook
	Target   string `yaml:"target"`   // telegram topic name
}

// Notifiers configuration.
type Notifiers struct {
	Telegram *Telegram `yaml:"telegram"`
	Webhook  *Webhook  `yaml:"webhook"`
}

// Telegram bot settings; topics map a target name to a forum topic (message_thread_id).
type Telegram struct {
	TokenEnv string         `yaml:"token_env"`
	ChatID   string         `yaml:"chat_id"`
	Topics   map[string]int `yaml:"topics"`
	BaseURL  string         `yaml:"base_url"`
}

// Webhook posts {"text": …} to a URL held in an environment variable.
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

// Roles: viewer sees status, incidents and charts; logs additionally sees log lines.
const (
	RoleViewer = "viewer"
	RoleLogs   = "logs"
)

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
	return Parse(b)
}

// Parse parses YAML, applies defaults, resolves secrets and validates.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.defaults()
	c.resolveSecrets()
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
	if t := c.Notifiers.Telegram; t != nil {
		add(t.TokenEnv)
	}
	if w := c.Notifiers.Webhook; w != nil {
		add(w.URLEnv)
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
		switch r.Notifier {
		case "telegram":
			if c.Notifiers.Telegram == nil {
				bad("routes.%s: notifier telegram is not configured", r.Name)
			} else if _, ok := c.Notifiers.Telegram.Topics[r.Target]; r.Target != "" && !ok {
				bad("routes.%s: telegram topic %q is not configured", r.Name, r.Target)
			}
		case "webhook":
			if c.Notifiers.Webhook == nil {
				bad("routes.%s: notifier webhook is not configured", r.Name)
			}
		default:
			bad("routes.%s: notifier must be telegram or webhook", r.Name)
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
		default:
			bad("rules.%s: type must be threshold, text, lograte or anomaly", r.Name)
		}
	}
	for i, p := range c.Probes {
		if p.Name == "" || p.URL == "" || !hasEnv(p.Env) {
			bad("probes[%d]: name, url and a configured env are required", i)
		}
	}
	if c.AI != nil && c.AI.Model == "" {
		bad("ai: model is required")
	}
	if c.Report != nil && !routes[c.Report.Route] {
		bad("report: route %q is not configured", c.Report.Route)
	}
	if c.Report != nil {
		if _, err := time.Parse("15:04", c.Report.At); err != nil {
			bad("report.at: want HH:MM (UTC)")
		}
	}
	for i, k := range c.Auth.APIKeys {
		if k.Role != RoleViewer && k.Role != RoleLogs {
			bad("auth.api_keys[%d]: role must be viewer or logs", i)
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
			if role != RoleViewer && role != RoleLogs {
				bad("auth.jwt[%d]: role %q must be viewer or logs", i, role)
			}
		}
	}
	return errors.Join(errs...)
}
