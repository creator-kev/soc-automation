# Changelog

All notable changes to `soc-automation` are documented here. The format is based on Keep a Changelog.

## 0.1.0 - 2026-06-23
### Added
- CSV and JSONL to Sigma rule conversion
- Explicit field mappings with transforms: raw, ip, url, domain, startswith, endswith, regex
- FastAPI web UI (`/` + `/api/convert`)
- CLI `sigma-conv` with `--format`, `--mapping`, `--level`, `--out`
- Pytest test suite with coverage for CSV, JSONL, transforms, and validation
- GitHub Actions CI workflow
- Docs: `docs/container-escape` writeup + cheatsheet + labs + quickref

## 0.0.0 - 2026-06-23
- Project scaffold and initial release
