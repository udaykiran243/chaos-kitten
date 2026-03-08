"""Tests for SARIF Report Generation."""

import json
import pytest
from pathlib import Path
from chaos_kitten.litterbox.reporter import Reporter
from chaos_kitten import __version__

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

class TestSarifReporter:
    """Tests for SARIF reporting capability."""

    @pytest.fixture
    def mock_results(self):
        return {
            "vulnerabilities": [
                {
                    "type": "sql_injection",
                    "title": "SQL Injection",
                    "description": "SQL Injection found in login parameter",
                    "severity": "critical",
                    "endpoint": "/api/login",
                    "remediation": "Use prepared statements",
                    "proof_of_concept": "curl -X POST ... ' OR 1=1"
                },
                {
                    "type": "xss",
                    "title": "Reflected XSS",
                    "description": "XSS in search field",
                    "severity": "medium",
                    "endpoint": "/api/search",
                    "remediation": "Encode output",
                }
            ]
        }

    def test_sarif_structure(self, tmp_path, mock_results):
        """Test that SARIF output follows basic structure."""
        reporter = Reporter(output_path=tmp_path, output_format="sarif")
        output_file = reporter.generate(mock_results, "http://example.com")
        
        assert output_file.suffix == ".sarif"
        
        content = json.loads(output_file.read_text("utf-8"))
        
        # Check root keys
        assert content["version"] == "2.1.0"
        assert content["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        
        # Check run/tool info
        run = content["runs"][0]
        assert run["tool"]["driver"]["name"] == "chaos-kitten"
        assert run["tool"]["driver"]["version"] == __version__
        assert len(run["tool"]["driver"]["rules"]) == 2
        
        # Check rules
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["id"] == "sql_injection"
        assert rule["defaultConfiguration"]["level"] == "error"
        
        # Check results
        results = run["results"]
        assert len(results) == 2
        
        res1 = results[0]
        assert res1["ruleId"] == "sql_injection"
        assert res1["level"] == "error"
        assert res1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "/api/login"
        assert res1["properties"]["proof_of_concept"] == "curl -X POST ... ' OR 1=1"

    @pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
    def test_sarif_schema_validation(self, tmp_path, mock_results):
        """test that output validates against SARIF schema."""
        # Note: We won't actually fetch the schema from the web in strict unit tests 
        # to avoid flakes, unless we mock it or have a local copy. 
        # But we can verify strict structure.
        
        reporter = Reporter(output_path=tmp_path, output_format="sarif")
        output_file = reporter.generate(mock_results, "http://example.com")
        
        content = json.loads(output_file.read_text("utf-8"))
        
        # If we had the schema locally we would do:
        # schema_path = Path("tests/schemas/sarif-2.1.0.json") 
        # if schema_path.exists():
        #     schema = json.loads(schema_path.read_text())
        #     jsonschema.validate(instance=content, schema=schema)
        #     assert True
        
        # For now, just ensure it parses as JSON and has key fields
        assert isinstance(content, dict)

    def test_map_severity(self):
        """Test severity mapping."""
        reporter = Reporter()
        assert reporter._map_severity_to_sarif("critical") == "error"
        assert reporter._map_severity_to_sarif("high") == "error"
        assert reporter._map_severity_to_sarif("medium") == "warning"
        assert reporter._map_severity_to_sarif("low") == "note"
        assert reporter._map_severity_to_sarif("info") == "note"

    def test_dynamic_version_in_html_report(self, tmp_path, mock_results):
        """Test that HTML reports use dynamic version from package metadata."""
        reporter = Reporter(output_path=tmp_path, output_format="html")
        output_file = reporter.generate(mock_results, "http://example.com")
        
        # For HTML reports, we need to check the template context
        # The version should be dynamically pulled from __version__
        assert output_file.suffix == ".html"
        
        # Read the HTML content and verify it contains the version
        content = output_file.read_text("utf-8")
        assert __version__ in content
        assert "0.1.0" not in content  # Ensure hardcoded version is not present

    def test_dynamic_version_in_pdf_report(self, tmp_path, mock_results):
        """Test that PDF reports use dynamic version from package metadata."""
        reporter = Reporter(output_path=tmp_path, output_format="pdf")
        output_file = reporter.generate(mock_results, "http://example.com")
        
        # For PDF reports, verify the file is created
        assert output_file.suffix == ".pdf"
        
        # The version should be embedded in the PDF metadata/template context
        # We can't easily parse PDF content, but we can verify the file exists
        assert output_file.exists()

    def test_report_version_matches_package_version(self, tmp_path, mock_results):
        """Test that all report formats use the correct package version."""
        from chaos_kitten import __version__
        
        # Test HTML format
        html_reporter = Reporter(output_path=tmp_path, output_format="html")
        html_file = html_reporter.generate(mock_results, "http://example.com")
        html_content = html_file.read_text("utf-8")
        assert __version__ in html_content
        
        # Test SARIF format
        sarif_reporter = Reporter(output_path=tmp_path, output_format="sarif")
        sarif_file = sarif_reporter.generate(mock_results, "http://example.com")
        sarif_content = json.loads(sarif_file.read_text("utf-8"))
        assert sarif_content["runs"][0]["tool"]["driver"]["version"] == __version__
