# soc-automation — Project Roadmap

**Status:** 2026-06-23 | **Milestone:** v0.1 — Sigma Rule Converter

## Current Task
- `[x]` Scaffold package: `sigma_converter`
- `[x]` Implement `CsvToSigmaConverter` (field mapping + heuristic inference)
- `[x]` Add pytest test suite (6 tests)
- `[x]` CLI entry point: `sigma-conv`
- `[x]` End-to-end run: CSV → Sigma output verified

## Done Today
- `src/sigma_converter/__init__.py`
- `src/sigma_converter/converter.py`
- `src/sigma_converter/cli.py`
- `tests/test_converter.py`
- `examples/http_access.csv`
- `pyproject.toml`

## Next
- [ ] Add JSON log parser support
- [ ] Support `|startswith`, `|endswith`, `|regex` transforms
- [ ] Integrate with `fleet` / `elastic-agent` output formats
- [ ] Add YAML Sigma output option
- [ ] GitHub Actions workflow: lint + test on push
