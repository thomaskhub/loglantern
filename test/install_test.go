package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallScript runs install.sh in a systemd container: install, update, refused update,
// uninstall and purge. Needs podman and privileges for systemd: LOGLANTERN_INSTALL_TEST=1.
func TestInstallScript(t *testing.T) {
	if os.Getenv("LOGLANTERN_INSTALL_TEST") != "1" {
		t.Skip("set LOGLANTERN_INSTALL_TEST=1 (podman, privileged systemd container)")
	}
	dir := t.TempDir()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	pkg := filepath.Join(dir, "pkg")
	_ = os.MkdirAll(pkg, 0o755)
	archive := func(version string) {
		run("go", "build", "-trimpath", "-ldflags", "-X main.version="+version, "-o", filepath.Join(pkg, "loglantern"), "../cmd/loglantern")
		run("cp", "-r", "../examples", "../install.sh", pkg)
		run("tar", "-czf", filepath.Join(dir, "ll-"+version+".tar.gz"), "-C", pkg, ".")
	}
	archive("1.0.0")
	archive("1.0.1")
	run("cp", "../install.sh", dir)
	run("podman", "build", "-q", "-t", "loglantern-install-test", "-f", "install/Containerfile", "install")
	name := "ll-install-test"
	_ = exec.Command("podman", "rm", "-f", name).Run()
	run("podman", "run", "-d", "--name", name, "--privileged", "--systemd=always", "-v", dir+":/inst:Z", "loglantern-install-test")
	defer exec.Command("podman", "rm", "-f", name).Run()
	sh := func(script string) (string, error) {
		out, err := exec.Command("podman", "exec", name, "sh", "-c", script).CombinedOutput()
		return string(out), err
	}
	must := func(script string) string {
		t.Helper()
		out, err := sh(script)
		if err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
		return out
	}
	for range 20 { // wait for systemd
		if out, _ := sh("systemctl is-system-running"); strings.Contains(out, "running") || strings.Contains(out, "degraded") {
			break
		}
		must("sleep 0.5")
	}

	out := must("sh /inst/install.sh --archive /inst/ll-1.0.0.tar.gz --env uat --checks")
	if !strings.Contains(out, "loglantern is running") || !strings.Contains(out, "LOGLANTERN_TOKEN=") {
		t.Fatalf("I1 install:\n%s", out)
	}
	if got := must(`. /etc/loglantern/secrets.env; curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $LOGLANTERN_TOKEN_UAT" -d '[{"host":"h1","MESSAGE":"x"}]' 127.0.0.1:8440/ingest`); got != "204" {
		t.Fatalf("I2 ingest with generated token: %s", got)
	}
	if got := must("stat -c '%a %U:%G' /etc/loglantern/secrets.env /etc/loglantern/config.yaml /var/lib/loglantern"); got != "600 root:root\n640 root:loglantern\n750 loglantern:loglantern\n" {
		t.Errorf("I3 permissions:\n%s", got)
	}
	must("systemctl start loglantern-checks.service")
	if got := must("journalctl -t loglantern-fact -o cat --no-pager"); !strings.Contains(got, `"fact":"mem"`) || strings.Contains(got, `"fact":"postgres"`) {
		t.Errorf("I4 checks (postgres check silent without postgres):\n%s", got)
	}
	before := must("md5sum /etc/loglantern/secrets.env /etc/loglantern/config.yaml")
	if out := must("sh /inst/install.sh --archive /inst/ll-1.0.1.tar.gz"); !strings.Contains(out, "1.0.0 -> 1.0.1") {
		t.Fatalf("I5 update:\n%s", out)
	}
	if after := must("md5sum /etc/loglantern/secrets.env /etc/loglantern/config.yaml"); after != before {
		t.Error("I6 update changed config or secrets")
	}
	must("cp /etc/loglantern/config.yaml /tmp/ok.yaml && echo 'rules: [{name: x, type: nope}]' >> /etc/loglantern/config.yaml")
	if out, err := sh("sh /inst/install.sh --archive /inst/ll-1.0.0.tar.gz"); err == nil || !strings.Contains(out, "nothing was changed") {
		t.Fatalf("I7 broken config accepted:\n%s", out)
	}
	if got := must("loglantern version; systemctl is-active loglantern"); got != "1.0.1\nactive\n" {
		t.Fatalf("I7 old binary must keep running: %q", got)
	}
	must("cp /tmp/ok.yaml /etc/loglantern/config.yaml")
	must("sh /inst/install.sh --uninstall")
	if got, _ := sh("test -e /usr/local/bin/loglantern && echo bin; test -f /etc/loglantern/config.yaml && echo cfg; systemctl is-active loglantern"); got != "cfg\ninactive\n" {
		t.Fatalf("I8 uninstall keeps config only: %q", got)
	}
	must("sh /inst/install.sh --purge")
	if got, _ := sh("ls -d /etc/loglantern /var/lib/loglantern 2>/dev/null; id loglantern 2>/dev/null"); got != "" {
		t.Fatalf("I9 purge left: %q", got)
	}
}
