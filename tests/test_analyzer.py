import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqli_detector.analyzer import SQLInjectionAnalyzer, analyze_file


class TestBasicDetection(unittest.TestCase):
    """Test basic SQL injection detection patterns."""

    def test_fstring_detection(self):
        """Test detection of f-string SQL injection."""
        code = '''
user_id = "123"
query = f"SELECT * FROM users WHERE id = {user_id}"
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        self.assertGreater(len(findings), 0)
        self.assertTrue(any('f-string' in f.vulnerability_type.lower() for f in findings))

    def test_concatenation_detection(self):
        """Test detection of string concatenation SQL injection."""
        code = '''
username = "admin"
query = "SELECT * FROM users WHERE username = '" + username + "'"
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        self.assertGreater(len(findings), 0)
        self.assertTrue(any('concatenation' in f.vulnerability_type.lower() for f in findings))

    def test_format_detection(self):
        """Test detection of .format() SQL injection."""
        code = '''
email = "test@example.com"
query = "SELECT * FROM users WHERE email = '{}'".format(email)
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        self.assertGreater(len(findings), 0)
        self.assertTrue(any('format' in f.vulnerability_type.lower() for f in findings))

    def test_safe_query_no_detection(self):
        """Test that safe parameterized queries are not flagged."""
        code = '''
import sqlite3
conn = sqlite3.connect('db.db')
cursor = conn.cursor()
user_id = "123"
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        # Should have minimal or no findings for properly parameterized query
        # (data flow might still flag the variable, but not the query itself)
        param_findings = [f for f in findings if 'parameterized' not in f.code.lower()]
        self.assertEqual(len([f for f in param_findings if '?' in f.code]), 0)


class TestDataFlowAnalysis(unittest.TestCase):
    """Test data flow analysis capabilities."""

    def test_user_input_tracking(self):
        """Test tracking of user input through variables."""
        code = '''
user_input = input("Enter ID: ")
user_id = user_input
query = f"SELECT * FROM users WHERE id = {user_id}"
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        self.assertGreater(len(findings), 0)
        taint_findings = [f for f in findings if 'tainted' in f.vulnerability_type.lower()]
        self.assertGreater(len(taint_findings), 0)

    def test_request_args_tracking(self):
        """Test tracking of Flask request.args."""
        code = '''
from flask import request
username = request.args.get('username')
query = f"SELECT * FROM users WHERE username = '{username}'"
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        self.assertGreater(len(findings), 0)
        user_input_findings = [f for f in findings if 'user_input' in f.vulnerability_type.lower()]
        self.assertGreater(len(user_input_findings), 0)

    def test_constant_no_taint(self):
        """Test that constants are not marked as tainted."""
        code = '''
table_name = "users"
query = f"SELECT * FROM {table_name}"
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        # Should only detect pattern-based issue, not data flow
        taint_findings = [f for f in findings if 'tainted' in f.vulnerability_type.lower()]
        # Constants shouldn't be tainted
        self.assertEqual(len(taint_findings), 0)


class TestSQLAlchemyDetection(unittest.TestCase):
    """Test SQLAlchemy-specific vulnerability detection."""

    def test_text_with_fstring(self):
        """Test detection of text() with f-string."""
        code = '''
from sqlalchemy import text
user_id = "123"
query = text(f"SELECT * FROM users WHERE id = {user_id}")
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        self.assertGreater(len(findings), 0)
        sa_findings = [f for f in findings if 'sqlalchemy' in f.vulnerability_type.lower()]
        self.assertGreater(len(sa_findings), 0)

    def test_text_with_concatenation(self):
        """Test detection of text() with string concatenation."""
        code = '''
from sqlalchemy import text
username = "admin"
query = text("SELECT * FROM users WHERE username = '" + username + "'")
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        self.assertGreater(len(findings), 0)
        sa_findings = [f for f in findings if 'sqlalchemy' in f.vulnerability_type.lower()]
        self.assertGreater(len(sa_findings), 0)

    def test_safe_bound_parameters(self):
        """Test that SQLAlchemy bound parameters are recognized as safe."""
        code = '''
from sqlalchemy import text
from sqlalchemy.orm import Session
user_id = "123"
query = text("SELECT * FROM users WHERE id = :user_id")
session.execute(query, {"user_id": user_id})
'''
        analyzer = SQLInjectionAnalyzer("test.py", code)
        findings = analyzer.analyze()

        # Should not flag the bound parameter usage
        sa_findings = [f for f in findings if 'sqlalchemy' in f.vulnerability_type.lower() and ':user_id' in f.code]
        self.assertEqual(len(sa_findings), 0)


class TestFileAnalysis(unittest.TestCase):
    """Test file-level analysis."""

    def test_analyze_vulnerable_file(self):
        """Test analyzing a file with vulnerabilities."""
        test_file = Path(__file__).parent.parent / "examples" / "vulnerable_code.py"

        if test_file.exists():
            findings = analyze_file(test_file)
            self.assertGreater(len(findings), 0)

    def test_analyze_safe_file(self):
        """Test analyzing a file with safe code."""
        test_file = Path(__file__).parent.parent / "examples" / "safe_code.py"

        if test_file.exists():
            findings = analyze_file(test_file)
            # Safe file should have no or very few findings
            self.assertLess(len(findings), 3)


if __name__ == '__main__':
    unittest.main()
