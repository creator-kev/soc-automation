"""Core converter: map custom log fields to Sigma rule conditions."""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from typing import Iterable, List


@dataclass
class FieldMapping:
    source: str
    sigma_field: str
    transform: str = "raw"  # raw | ip | url | domain | regex


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
            lines.append("fields:")
            for f in self.fields:
                lines.append(f"  - {f}")
        lines.append("detection:")
        lines.append("  selection:")
        if self.conditions:
            for c in self.conditions:
                lines.append(f"    {c}")
        else:
            lines.append("    dummy: '*'")
        lines.append("  timeframe: 5m")
        lines.append("  condition: selection")
        if self.falsepositives:
            lines.append("falsepositives:")
            for fp in self.falsepositives:
                lines.append(f"  - {fp}")
        if self.references:
            lines.append("references:")
            for ref in self.references:
                lines.append(f"  - {ref}")
        return "\n".join(lines).format(**self.__dict__)


class CsvToSigmaConverter:
    """Convert CSV-formatted application logs into Sigma rules via field mappings."""

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
            "remote": FieldMapping("remote", "src_ip", "ip"),
            "request": FieldMapping("request", "request", "url"),
            "url": FieldMapping("url", "url", "url"),
            "path": FieldMapping("path", "request", "raw"),
            "status": FieldMapping("status", "status", "raw"),
            "agent": FieldMapping("user_agent", "user_agent", "raw"),
            "user_agent": FieldMapping("user_agent", "user_agent", "raw"),
            "message": FieldMapping("message", "message", "raw"),
            "method": FieldMapping("method", "http_method", "raw"),
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
            return re.sub(r"^https?://([^/]+).*$", r"\1", v)
        if transform == "regex" and not (v.startswith("/") and v.endswith("/")):
            return f"/{re.escape(v)}/i"
        return v

    def convert(self, csv_data: str, rule: DetectionRule) -> str:
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

        # Build conditions from unique record values
        condition_counts = {}
        for row in reader:
            pieces = []
            for sigma_field, col in field_to_col.items():
                raw = row.get(col, "")
                value = self._transform_value(raw, next((m.transform for m in self.mappings if m.sigma_field == sigma_field), "raw"))
                if value:
                    pieces.append(f"{sigma_field}|contains='{value}'")

            key = " and ".join(pieces)
            condition_counts[key] = condition_counts.get(key, 0) + 1

        rule.conditions = [c for c, _ in sorted(condition_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]]
        rule.fields = sorted({m.sigma_field for m in self.mappings} | set(field_to_col.keys()))
        return rule.render()
