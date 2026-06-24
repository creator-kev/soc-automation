# soc-automation — Project Roadmap

**Status:** 2026-06-23 | **Milestone:** v0.1 — Sigma Rule Converter

## Current Task
- `[x]` Scaffold package: `sigma_converter`
- `[x]` Implement `CsvToSigmaConverter` (field mapping + heuristic inference)
- `[x]` Add pytest test suite
- `[x]` CLI entry point: `sigma-conv`
- `[x]` FastAPI web UI (`/` + `/api/convert`)
- `[x]` End-to-end run: CSV → Sigma output verified
- `[x]` CI + docs + GitHub push

## Done Today
- `src/sigma_converter/*`
- `tests/test_converter.py`
- `examples/http_access.csv`, `examples/http_access.jsonl`
- `web/templates/index.html`
- `.github/workflows/ci.yml`
- `docs/container-escape/` (knowledge pack added)

## Next
- `[ ]` v0.2: add JSON log parser + transforms
- `[ ]` Integrate with `fleet` / `elastic-agent` output formats
- `[ ]` SOC playbook pack (cloud, AD, network rules)
