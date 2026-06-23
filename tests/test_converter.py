"""Tests for the Sigma converter."""
from __future__ import annotations

import json
from textwrap import dedent

import pytest
from sigma_converter import CsvToSigmaConverter
from sigma_converter.converter import FieldMapping, DetectionRule


@pytest.fixture
def converter():
    return CsvToSigmaConverter(
        mappings=[
            FieldMapping("client", "src_ip", "ip"),
            FieldMapping("request", "request", "url"),
            FieldMapping("status", "status", "raw"),
            FieldMapping("user_agent", "user_agent", "raw"),
        ]
    )


@pytest.fixture
def rule():
    return DetectionRule(
        title="Test HTTP Access Rule",
        id="abc123",
        description="Auto-generated test rule",
        author="soc-automation",
        date="2026-06-23",
        level="medium",
    )


SAMPLE_CSV = dedent(
    """
    client,request,status,user_agent
    10.0.0.1,"GET /admin HTTP/1.1",200,"curl/7.68"
    10.0.0.2,"POST /login HTTP/1.1",401,"httpie/3.0"
    10.0.0.1,"GET /admin HTTP/1.1",200,"curl/7.68"
    """
).strip()


EMPTY_CSV = "header1,header2\n"


def test_convert_produces_sigma_title(converter, rule):
    out = converter.convert_csv(SAMPLE_CSV, rule)
    assert "title: Test HTTP Access Rule" in out


def test_convert_produces_id(converter, rule):
    out = converter.convert_csv(SAMPLE_CSV, rule)
    assert "id: abc123" in out


def test_convert_produces_detection_block(converter, rule):
    out = converter.convert_csv(SAMPLE_CSV, rule)
    assert "detection:" in out
    assert "selection:" in out


def test_convert_uses_src_ip_mapping(converter, rule):
    out = converter.convert_csv(SAMPLE_CSV, rule)
    assert "src_ip" in out


def test_convert_http_method_heuristic():
    data = "method,path,status\nGET,/admin,200\nPOST,/login,401\n"
    conv = CsvToSigmaConverter()
    rule = DetectionRule(
        title="HTTP Heuristic Rule",
        id="def456",
        description="Heuristic test",
        author="tester",
        date="2026-06-23",
        level="medium",
    )
    out = conv.convert_csv(data, rule)
    assert "http_method" in out


def test_detection_rule_render_round_trip():
    r = DetectionRule(
        title="Round Trip",
        id="r1",
        description="x",
        author="a",
        date="2026-01-01",
        level="high",
    )
    rendered = r.render()
    assert rendered.startswith("title: Round Trip")
    assert "id: r1" in rendered


def test_convert_csv_rejects_empty_header():
    conv = CsvToSigmaConverter()
    rule = DetectionRule(title="T", id="x", date="2026-01-01")
    with pytest.raises(ValueError):
        conv.convert_csv("", rule)


def test_convert_csv_with_explicit_rule_title():
    conv = CsvToSigmaConverter()
    rule = DetectionRule(title="My Rule", id="my-rule", date="2026-01-01")
    out = conv.convert_csv("a,b\n1,2\n", rule)
    assert out.startswith("title: My Rule")


def test_convert_jsonl_requires_mappings():
    conv = CsvToSigmaConverter()
    rule = DetectionRule(title="JSONL", id="j1", date="2026-01-01")
    with pytest.raises(ValueError):
        conv.convert_jsonl('{"a":1}\n', rule)


def test_convert_jsonl_extracts_nested_field():
    mappings = [FieldMapping("source.src", "src_ip", "ip")]
    conv = CsvToSigmaConverter(mappings=mappings)
    rule = DetectionRule(title="JSONL Nested", id="j2", date="2026-01-01")
    data = json.dumps({"source": {"src": "1.2.3.4"}}) + "\n"
    out = conv.convert_jsonl(data, rule)
    assert "src_ip|contains='1.2.3.4'" in out


def test_convert_preserves_high_cardinality_top_conditions():
    conv = CsvToSigmaConverter(
        mappings=[FieldMapping("client", "src_ip", "ip")]
    )
    rule = DetectionRule(title="Top", id="t", date="2026-01-01")
    rows = "\n".join(
        f"10.0.0.{i}" for i in range(1, 51)
    )
    out = conv.convert_csv(f"client\n{rows}", rule)
    assert "src_ip|contains='10.0.0.1'" in out


def test_field_mapping_transform_startswith():
    conv = CsvToSigmaConverter(
        mappings=[FieldMapping("path", "request", "startswith")]
    )
    rule = DetectionRule(title="SW", id="s", date="2026-01-01")
    data = "path\n/etc/ \n"
    out = conv.convert_csv(data, rule)
    assert "/etc/*" in out


def test_field_mapping_transform_endswith():
    conv = CsvToSigmaConverter(
        mappings=[FieldMapping("path", "request", "endswith")]
    )
    rule = DetectionRule(title="EW", id="e", date="2026-01-01")
    data = "path\n/.env\n"
    out = conv.convert_csv(data, rule)
    assert "*/.env" in out


def test_field_mapping_transform_regex():
    conv = CsvToSigmaConverter(
        mappings=[FieldMapping("pattern", "pattern", "regex")]
    )
    rule = DetectionRule(title="RE", id="r", date="2026-01-01")
    data = "pattern\nadmin\n"
    out = conv.convert_csv(data, rule)
    assert "/admin/i" in out


def test_convert_empty_data_does_not_crash():
    conv = CsvToSigmaConverter()
    rule = DetectionRule(title="E", id="e", date="2026-01-01")
    out = conv.convert_csv("header1\n", rule)
    assert "title: E" in out
