"""
Tests for Command Injection detection
"""
import unittest
from sqli_detector.command_injection_analyzer import CommandInjectionAnalyzer


class TestCommandInjectionDetection(unittest.TestCase):
    """Test cases for command injection detection."""

    def test_os_system_with_user_input(self):
        """Test detection of os.system with user input."""
        code = '''
import os
filename = input("Enter filename: ")
os.system(f"cat {filename}")
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)
        self.assertIn("os.system", vulnerabilities[0][2])

    def test_subprocess_with_shell_true(self):
        """Test detection of subprocess with shell=True."""
        code = '''
import subprocess
user_input = input("Enter command: ")
subprocess.run(f"ls {user_input}", shell=True)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)
        self.assertIn("shell=True", vulnerabilities[0][2])

    def test_safe_subprocess_list(self):
        """Test that subprocess with list args is safe."""
        code = '''
import subprocess
user_file = input("File: ")
subprocess.run(["cat", user_file])
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 0)

    def test_os_popen_with_fstring(self):
        """Test detection of os.popen with f-string."""
        code = '''
import os
directory = input("Directory: ")
os.popen(f"ls -la {directory}")
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)
        self.assertIn("os.popen", vulnerabilities[0][2])

    def test_eval_with_user_input(self):
        """Test detection of eval with user input."""
        code = '''
user_code = input("Enter expression: ")
result = eval(user_code)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)
        self.assertIn("eval", vulnerabilities[0][2])

    def test_exec_with_user_input(self):
        """Test detection of exec with user input."""
        code = '''
user_code = input("Enter code: ")
exec(user_code)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)
        self.assertIn("exec", vulnerabilities[0][2])

    def test_subprocess_check_output_vulnerable(self):
        """Test detection of subprocess.check_output with shell=True."""
        code = '''
import subprocess
hostname = input("Enter hostname: ")
output = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)

    def test_string_concatenation(self):
        """Test detection of string concatenation with commands."""
        code = '''
import subprocess
user_file = input("File: ")
subprocess.call("grep pattern " + user_file, shell=True)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)

    def test_format_method(self):
        """Test detection of .format() with commands."""
        code = '''
import os
target = input("Target: ")
cmd = "nmap {}".format(target)
os.system(cmd)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)

    def test_safe_hardcoded_command(self):
        """Test that hardcoded commands are safe."""
        code = '''
import os
import subprocess
os.system("ls -la /tmp")
subprocess.run("date", shell=True)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 0)

    def test_safe_subprocess_no_shell(self):
        """Test that subprocess with shell=False is safe."""
        code = '''
import subprocess
user_input = input("Search term: ")
subprocess.run(["grep", user_input, "file.txt"], shell=False)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 0)

    def test_tainted_variable_tracking(self):
        """Test tracking of tainted variables through assignments."""
        code = '''
import os
user_input = input("Enter value: ")
command = user_input
os.system(command)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)

    def test_multiple_tainted_vars(self):
        """Test multiple tainted variables in one command."""
        code = '''
import os
host = input("Host: ")
port = input("Port: ")
os.system(f"nc -zv {host} {port}")
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)

    def test_subprocess_popen_list_safe(self):
        """Test that subprocess.Popen with list is safe."""
        code = '''
import subprocess
user_arg = input("Argument: ")
proc = subprocess.Popen(["echo", user_arg])
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 0)

    def test_subprocess_call_vulnerable(self):
        """Test detection of subprocess.call with tainted data."""
        code = '''
import subprocess
filename = input("File: ")
subprocess.call(f"cat {filename}", shell=True)
'''
        analyzer = CommandInjectionAnalyzer("test.py", code)
        vulnerabilities = analyzer.analyze()
        self.assertEqual(len(vulnerabilities), 1)


if __name__ == '__main__':
    unittest.main()
