"""Tests for the Sigma converter."""
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


SAMPLE_CSV = """client,request,status,user_agent
10.0.0.1,"GET /admin HTTP/1.1",200,"curl/7.68"
10.0.0.2,"POST /login HTTP/1.1",401,"httpie/3.0"
10.0.0.1,"GET /admin HTTP/1.1",200,"curl/7.68"
"""


def test_convert_produces_sigma_title(converter, rule):
    out = converter.convert(SAMPLE_CSV, rule)
    assert "title: Test HTTP Access Rule" in out


def test_convert_produces_id(converter, rule):
    out = converter.convert(SAMPLE_CSV, rule)
    assert "id: abc123" in out


def test_convert_produces_conditions(converter, rule):
    out = converter.convert(SAMPLE_CSV, rule)
    assert "detection:" in out
    assert "selection:" in out


def test_convert_uses_src_ip_mapping(converter, rule):
    out = converter.convert(SAMPLE_CSV, rule)
    assert "src_ip" in out


def test_convert_uses_http_method_heuristically():
    csv_data = "method,path,status\nGET,/admin,200\nPOST,/login,401\n"
    conv = CsvToSigmaConverter()
    rule = DetectionRule(
        title="HTTP Heuristic Rule",
        id="def456",
        description="Heuristic test",
        author="tester",
        date="2026-06-23",
        level="medium",
    )
    out = conv.convert(csv_data, rule)
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
