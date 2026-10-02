package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(filepath.Join(dir, "secrets.env"), []byte("# c\nLL_A=one\nexport LL_B=\"two words\"\nLL_C='x=y'\n\nLL_SET=from-file\n"), 0o600)
	t.Setenv("LL_SET", "from-env")
	for _, k := range []string{"LL_A", "LL_B", "LL_C"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	if err := loadEnvFile("auto", cfg); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"LL_A": "one", "LL_B": "two words", "LL_C": "x=y", "LL_SET": "from-env"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if err := loadEnvFile("auto", filepath.Join(t.TempDir(), "c.yaml")); err != nil {
		t.Errorf("auto without file: %v", err)
	}
	unreadable := filepath.Join(t.TempDir(), "config.yaml")
	_ = os.Mkdir(filepath.Join(filepath.Dir(unreadable), "secrets.env"), 0o700) // a directory: read fails
	if err := loadEnvFile("auto", unreadable); err != nil {
		t.Errorf("auto with unreadable file must be ignored: %v", err)
	}
	if err := loadEnvFile("/nonexistent", cfg); err == nil {
		t.Error("explicit missing file accepted")
	}
	bad := filepath.Join(dir, "bad.env")
	_ = os.WriteFile(bad, []byte("NOEQUALS\n"), 0o600)
	if err := loadEnvFile(bad, cfg); err == nil {
		t.Error("bad line accepted")
	}
}
