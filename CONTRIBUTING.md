# Contributing to promptshield

Thanks for your interest! Pull requests of any size are welcome.

## Setup

```bash
git clone https://github.com/dokienlam/promptshield && cd promptshield
go test ./...
go build .
./promptshield
```

The project is a single Go package (~1.5k LoC). No build system, no codegen, no framework. If you can read Go, you can ship a PR.

## What's most helpful

1. **New detection rules** — for prompt injection, jailbreak, PII, or secret leakage. Each rule should come with at least one positive test (input that should match) and one negative test (similar input that shouldn't trigger a false positive). See `detector_test.go` for examples.

2. **Bug reports** — if a benign request is being blocked, or if a known attack pattern slips through, please file an issue with a reproducer.

3. **Provider support** — currently OpenAI, Anthropic, Gemini. PRs welcome for Cohere, Mistral, Together, Groq, Ollama, etc.

4. **Translations** — the dashboard is currently English-only.

## Code style

- `gofmt` everything (CI will fail otherwise).
- Keep the project a single package unless there's a clear reason to split.
- New regex rules should be conservative — false positives are worse than missing one attack pattern. We can add overlapping rules to catch what we miss.

## Pull request checklist

- [ ] `go test ./...` passes
- [ ] `gofmt -l .` is empty
- [ ] `go vet ./...` is clean
- [ ] New detector rules have positive + negative tests
- [ ] README updated if user-facing behavior changes

## Releases

Maintainers tag versions as `v0.x.y` following SemVer. CI builds artifacts on tag push.

## License

By contributing, you agree your contribution will be licensed under the [MIT License](LICENSE).
