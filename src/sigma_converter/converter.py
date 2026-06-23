"""Core converter: map custom log fields to Sigma rule conditions."""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, List


@dataclass(frozen=True)
class FieldMapping:
    source: str
    sigma_field: str
    transform: str = "raw"  # raw | ip | url | domain | startswith | endswith | regex


@dataclass
class DetectionRule:
    title: str
    id: str
    status: str = "stable"
    description: str = ""
    author: str = ""
    date: str = ""
    level: str = "medium"
    fields: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            "title: {title}",
            "id: {id}",
            "status: {status}",
            "description: {description}",
            "author: {author}",
            "date: {date}",
            "level: {level}",
        ]
        if self.fields:
            lines.extend(["fields:", *(f"  - {f}" for f in self.fields)])
        lines.extend(
            [
                "detection:",
                "  selection:",
                *(
                    f"    {c}"
                    for c in (self.conditions or ["dummy: '*'"])
                ),
                "  timeframe: 5m",
                "  condition: selection",
            ]
        )
        if self.falsepositives:
            lines.extend(["falsepositives:", *(f"  - {fp}" for fp in self.falsepositives)])
        if self.references:
            lines.extend(["references:", *(f"  - {r}" for r in self.references)])
        return "\n".join(lines).format(**self.__dict__)


class CsvToSigmaConverter:
    """Convert CSV/JSON-formatted application logs into Sigma rules via field mappings."""

    def __init__(self, mappings: Iterable[FieldMapping] | None = None) -> None:
        self.mappings = list(mappings or [])

    def infer_mappings_from_header(self, header: str) -> None:
        if self.mappings:
            return
        h = header.lower()
        heur = {
            "ip": FieldMapping("ip", "src_ip", "ip"),
            "source": FieldMapping("source", "src_ip", "ip"),
            "client": FieldMapping("client", "src_ip", "ip"),
            "remote_addr": FieldMapping("remote_addr", "src_ip", "ip"),
            "remote": FieldMapping("remote", "src_ip", "ip"),
            "request": FieldMapping("request", "request", "url"),
            "url": FieldMapping("url", "url", "url"),
            "path": FieldMapping("path", "request", "raw"),
            "status": FieldMapping("status", "status", "raw"),
            "agent": FieldMapping("user_agent", "user_agent", "raw"),
            "user_agent": FieldMapping("user_agent", "user_agent", "raw"),
            "message": FieldMapping("message", "message", "raw"),
            "method": FieldMapping("method", "http_method", "raw"),
            "http_method": FieldMapping("http_method", "http_method", "raw"),
            "destination_ip": FieldMapping("destination_ip", "dest_ip", "ip"),
            "dest_ip": FieldMapping("dest_ip", "dest_ip", "ip"),
        }
        for token, mapping in heur.items():
            if token in h and mapping not in self.mappings:
                self.mappings.append(mapping)

    def _transform_value(self, value: str, transform: str) -> str:
        v = value.strip().strip('"').strip("'")
        if transform == "ip":
            return v
        if transform == "url":
            return re.sub(r"\s+", " ", v)
        if transform == "domain":
            m = re.search(r"https?://([^/]+)", v)
            return m.group(1) if m else v
        if transform == "startswith" and not v.startswith("*"):
            return f"{v}*"
        if transform == "endswith" and not v.endswith("*"):
            return f"*{v}"
        if transform == "regex" and not (v.startswith("/") and v.endswith("/")):
            return f"/{re.escape(v)}/i"
        return v

    def _apply_mapping(self, sigma_field: str, raw: str) -> str | None:
        transform = next(
            (m.transform for m in self.mappings if m.sigma_field == sigma_field), "raw"
        )
        return self._transform_value(raw, transform) or None

    def convert_csv(self, csv_data: str, rule: DetectionRule) -> str:
        reader = csv.DictReader(io.StringIO(csv_data))
        if not reader.fieldnames:
            raise ValueError("CSV must contain a header row")

        if not self.mappings:
            self.infer_mappings_from_header(",".join(reader.fieldnames))

        field_to_col = {}
        for m in self.mappings:
            for col in reader.fieldnames:
                if col.lower() in (m.source.lower(), m.sigma_field.lower()):
                    field_to_col[m.sigma_field] = col
                    break

        condition_counts: dict[str, int] = {}
        for row in reader:
            pieces: list[str] = []
            for sigma_field, col in field_to_col.items():
                raw = row.get(col, "")
                value = self._apply_mapping(sigma_field, raw)
                if value:
                    pieces.append(f"{sigma_field}|contains='{value}'")

            key = " and ".join(pieces)
            condition_counts[key] = condition_counts.get(key, 0) + 1

        rule.conditions = [
            c
            for c, _ in sorted(
                condition_counts.items(), key=lambda kv: kv[1], reverse=True
            )[:10]
        ]
        rule.fields = sorted(
            {m.sigma_field for m in self.mappings} | set(field_to_col.keys())
        )
        return rule.render()

    def convert_jsonl(self, jsonl_data: str, rule: DetectionRule) -> str:
        """Treat each line as a JSON object and extract the first matching leaf values per mapped field."""
        if not self.mappings:
            raise ValueError("JSONL conversion requires explicit FieldMapping list")
        condition_counts: dict[str, int] = {}
        fields_seen: set[str] = set()
        for line in jsonl_data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            pieces: list[str] = []
            for m in self.mappings:
                value = _resolve(obj, m.source)
                if value is None:
                    continue
                transformed = self._apply_mapping(m.sigma_field, str(value))
                if transformed:
                    pieces.append(f"{m.sigma_field}|contains='{transformed}'")
                fields_seen.add(m.sigma_field)
            key = " and ".join(pieces)
            condition_counts[key] = condition_counts.get(key, 0) + 1

        rule.conditions = [
            c
            for c, _ in sorted(
                condition_counts.items(), key=lambda kv: kv[1], reverse=True
            )[:10]
        ]
        rule.fields = sorted(fields_seen)
        return rule.render()


def _resolve(node: Any, path: str) -> Any:
    if not path:
        return None
    parts = re.split(r"\.(?![^\[]*\])", path)
    current = node
    for part in parts:
        if current is None:
            return None
        m = re.match(r"^([^\[]+)(?:\[(\d+)\])?$", part)
        if not m:
            return None
        key, idx = m.group(1), m.group(2)
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
        if idx is not None and isinstance(current, list):
            idx_i = int(idx)
            current = current[idx_i] if -len(current) <= idx_i < len(current) else None
    return current
