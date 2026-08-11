import ast
from typing import List, Dict, Any
from pathlib import Path
from .dataflow import DataFlowAnalyzer, TaintSource
from .sqlalchemy_analyzer import SQLAlchemyAnalyzer
from .command_injection_analyzer import CommandInjectionAnalyzer


class SQLInjectionFinding:
    """Represents a potential SQL injection vulnerability."""

    def __init__(self, filename: str, line: int, code: str, vulnerability_type: str, recommendation: str):
        self.filename = filename
        self.line = line
        self.code = code
        self.vulnerability_type = vulnerability_type
        self.recommendation = recommendation

    def __repr__(self):
        return f"SQLInjectionFinding({self.filename}:{self.line}, type={self.vulnerability_type})"


class SQLInjectionAnalyzer(ast.NodeVisitor):
    """AST-based analyzer for detecting SQL injection vulnerabilities."""

    SQL_KEYWORDS = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
        'ALTER', 'TRUNCATE', 'EXEC', 'EXECUTE', 'UNION', 'WHERE'
    }

    def __init__(self, filename: str, source_code: str):
        self.filename = filename
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.findings: List[SQLInjectionFinding] = []

    def analyze(self) -> List[SQLInjectionFinding]:
        """Run the analysis on the source code."""
        try:
            tree = ast.parse(self.source_code)
            self.visit(tree)

            # Run data flow analysis
            self._run_dataflow_analysis()

            # Run SQLAlchemy-specific analysis
            self._run_sqlalchemy_analysis()

            # Run command injection analysis
            self._run_command_injection_analysis()
        except SyntaxError as e:
            print(f"Warning: Could not parse {self.filename}: {e}")
        return self.findings

    def _run_dataflow_analysis(self):
        """Run data flow analysis to detect tainted variables in SQL."""
        df_analyzer = DataFlowAnalyzer(self.filename, self.source_code)
        tainted_uses = df_analyzer.analyze()

        for lineno, code_line, tainted_var in tainted_uses:
            self.findings.append(SQLInjectionFinding(
                filename=self.filename,
                line=lineno,
                code=code_line,
                vulnerability_type=f"Tainted data flow: {tainted_var.source.value}",
                recommendation=f"Variable '{tainted_var.name}' contains {tainted_var.source.value} data (defined at line {tainted_var.lineno}). Use parameterized queries to safely include this data."
            ))

    def _run_sqlalchemy_analysis(self):
        """Run SQLAlchemy-specific analysis."""
        sa_analyzer = SQLAlchemyAnalyzer(self.filename, self.source_code)
        vulnerabilities = sa_analyzer.analyze()

        for lineno, code_line, vuln_type in vulnerabilities:
            self.findings.append(SQLInjectionFinding(
                filename=self.filename,
                line=lineno,
                code=code_line,
                vulnerability_type=vuln_type,
                recommendation="Use SQLAlchemy bound parameters: text('SELECT * FROM users WHERE id = :id') with params={'id': value}"
            ))

    def _run_command_injection_analysis(self):
        """Run command injection analysis."""
        ci_analyzer = CommandInjectionAnalyzer(self.filename, self.source_code)
        vulnerabilities = ci_analyzer.analyze()

        for lineno, code_line, vuln_type in vulnerabilities:
            self.findings.append(SQLInjectionFinding(
                filename=self.filename,
                line=lineno,
                code=code_line,
                vulnerability_type=vuln_type,
                recommendation="Use subprocess with list arguments instead of shell=True: subprocess.run(['command', user_input])"
            ))

    def _is_sql_context(self, s: str) -> bool:
        """Check if a string contains SQL keywords."""
        s_upper = s.upper()
        return any(keyword in s_upper for keyword in self.SQL_KEYWORDS)

    def _get_source_line(self, lineno: int) -> str:
        """Get the source code line."""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Detect f-strings with SQL content."""
        try:
            # Reconstruct f-string for analysis
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    if self._is_sql_context(value.value):
                        # Found SQL in f-string
                        code_line = self._get_source_line(node.lineno)
                        self.findings.append(SQLInjectionFinding(
                            filename=self.filename,
                            line=node.lineno,
                            code=code_line,
                            vulnerability_type="f-string SQL injection",
                            recommendation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                        ))
                        break
        except Exception:
            pass

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        """Detect string concatenation with SQL."""
        if isinstance(node.op, ast.Add):
            # Check if left side is a string with SQL
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                if self._is_sql_context(node.left.value):
                    code_line = self._get_source_line(node.lineno)
                    self.findings.append(SQLInjectionFinding(
                        filename=self.filename,
                        line=node.lineno,
                        code=code_line,
                        vulnerability_type="String concatenation SQL injection",
                        recommendation="Use parameterized queries instead of string concatenation"
                    ))

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Detect .format() and % formatting with SQL."""
        # Check for .format()
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                if self._is_sql_context(node.func.value.value):
                    code_line = self._get_source_line(node.lineno)
                    self.findings.append(SQLInjectionFinding(
                        filename=self.filename,
                        line=node.lineno,
                        code=code_line,
                        vulnerability_type=".format() SQL injection",
                        recommendation="Use parameterized queries instead of .format()"
                    ))

        self.generic_visit(node)

    def visit_Mod(self, node: ast.Mod):
        """Detect % string formatting with SQL."""
        # This is handled in BinOp but we track it separately
        self.generic_visit(node)


def analyze_file(filepath: Path) -> List[SQLInjectionFinding]:
    """Analyze a single Python file for SQL injection vulnerabilities."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source_code = f.read()

        analyzer = SQLInjectionAnalyzer(str(filepath), source_code)
        return analyzer.analyze()
    except Exception as e:
        print(f"Error analyzing {filepath}: {e}")
        return []


def analyze_directory(directory: Path) -> Dict[str, List[SQLInjectionFinding]]:
    """Recursively analyze all Python files in a directory."""
    results = {}

    for py_file in directory.rglob("*.py"):
        findings = analyze_file(py_file)
        if findings:
            results[str(py_file)] = findings

    return results
