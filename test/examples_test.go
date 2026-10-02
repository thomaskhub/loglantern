package test

import (
	"testing"

	"github.com/thomkin/loglantern/internal/config"
)

// The example config stays valid as the code changes.
func TestExampleConfig(t *testing.T) {
	for _, v := range []string{"LOGLANTERN_TOKEN_UAT", "LOGLANTERN_TOKEN_PROD", "OPENROUTER_API_KEY"} {
		t.Setenv(v, "x")
	}
	t.Setenv("LOGLANTERN_KEY_BOARD", "0123456789abcdefgh")
	t.Setenv("LOGLANTERN_KEY_OPS", "0123456789abcdefgh")
	c, err := config.Load("../examples/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) < 10 || len(c.Notifiers) != 4 || len(c.AI.Agents) != 3 || len(c.Maintenance) != 2 {
		t.Fatalf("example lost content: %d rules, %d notifiers", len(c.Rules), len(c.Notifiers))
	}
}
