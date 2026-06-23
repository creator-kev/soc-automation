# soc-automation

Convert raw application logs into [Sigma](https://github.com/SigmaHQ/sigma) detection rules with field mapping, transforms, validation-friendly structure, and a minimal web UI.

**Why this exists:** SOCs and red teams often have to hand-roll detection rules from weird log formats. This tool maps your source fields to a Sigma-compatible model, infers common HTTP/network fields, and renders a ready-to-use rule in seconds.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[web,dev]"
```

## CLI

```bash
sigma-conv examples/http_access.csv "HTTP Admin Access"
sigma-conv examples/http_access.jsonl "JSONL HTTP Access" --format jsonl
```

Arguments:
- `INPUT` — input log file path
- `TITLE` — Sigma rule title
- `--format` — input format: `csv` (default) or `jsonl`
- `--out` — write rule to file instead of stdout
- `--level` — rule severity: `low`, `medium`, `high`, `critical`
- `--mapping` — field mappings in `source:sigma_field:transform` form (repeatable)
- `--id` — forced rule UUID

Web UI:
```bash
sigma-web
# open http://localhost:8080
```

## Field mapping

| Transform | Behavior |
|---|---|
| `raw` | passthrough as `contains` |
| `ip` | passthrough; reserved for src/dest IP |
| `url` | collapses whitespace in URLs |
| `domain` | strips scheme/path, keeps host |
| `startswith` | becomes `value*` |
| `endswith` | becomes `*value` |
| `regex` | wraps in `/pattern/i` |

## Repo layout

```
/app
├── pyproject.toml
├── README.md
├── STRUCTURE.md
├── src/sigma_converter/
│   ├── __init__.py
│   ├── converter.py
│   ├── cli.py
│   └── web_app.py
├── tests/test_converter.py
├── examples/http_access.csv
├── examples/http_access.jsonl
├── web/templates/index.html
└── .github/workflows/ci.yml
```

## CI

GitHub Actions runs:
- install with extras `web,dev`
- `pytest`
- build sanity check: `python -c "import sigma_converter"`

