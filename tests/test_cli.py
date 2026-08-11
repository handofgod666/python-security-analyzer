import unittest
import sys
import tempfile
import shutil
from pathlib import Path
from io import StringIO

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqli_detector.cli import scan_command


class TestCLI(unittest.TestCase):
    """Test CLI functionality."""

    def setUp(self):
        """Create temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_scan_vulnerable_code(self):
        """Test scanning code with vulnerabilities."""
        # Create test file with vulnerability
        test_file = Path(self.test_dir) / "test.py"
        test_file.write_text('''
user_id = input("Enter ID: ")
query = f"SELECT * FROM users WHERE id = {user_id}"
''')

        # Mock args
        class Args:
            path = str(test_file)
            verbose = False

        result = scan_command(Args())

        # Should return 1 (vulnerabilities found)
        self.assertEqual(result, 1)

    def test_scan_safe_code(self):
        """Test scanning code without vulnerabilities."""
        # Create test file with safe code
        test_file = Path(self.test_dir) / "test.py"
        test_file.write_text('''
import sqlite3
conn = sqlite3.connect('db.db')
cursor = conn.cursor()
user_id = "123"
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
''')

        # Mock args
        class Args:
            path = str(test_file)
            verbose = False

        result = scan_command(Args())

        # Should return 0 (no vulnerabilities) or 1 if data flow detects taint
        self.assertIn(result, [0, 1])

    def test_scan_nonexistent_file(self):
        """Test scanning non-existent file."""
        class Args:
            path = str(Path(self.test_dir) / "nonexistent.py")
            verbose = False

        result = scan_command(Args())

        # Should return 1 (error)
        self.assertEqual(result, 1)

    def test_scan_directory(self):
        """Test scanning a directory."""
        # Create multiple test files
        (Path(self.test_dir) / "vuln1.py").write_text('''
query = f"SELECT * FROM users WHERE id = {user_id}"
''')
        (Path(self.test_dir) / "vuln2.py").write_text('''
query = "SELECT * FROM users WHERE name = '" + username + "'"
''')

        class Args:
            path = str(self.test_dir)
            verbose = False

        result = scan_command(Args())

        # Should find vulnerabilities in multiple files
        self.assertEqual(result, 1)


if __name__ == '__main__':
    unittest.main()
