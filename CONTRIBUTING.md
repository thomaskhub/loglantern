# Contributing

Issues and pull requests are welcome.

- Run `gofmt`, `go vet ./...` and `go test -race ./...` before opening a pull request.
  The Fluent Bit end-to-end test needs `podman`; it is skipped without it.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat(notify): …`, `fix: …`).
- Keep dependencies few. New dependencies need a permissive license (MIT, BSD, Apache-2.0).
- Features come with tests. For rules, incidents and notifications, include the restart case.
- A new notifier: add a section to `config.Notifier` (with validation), a `Send` implementation in
  `internal/notify`, tests with a fake server, and a row in the README table.
