import ast
from typing import List, Tuple, Optional


class SQLAlchemyAnalyzer(ast.NodeVisitor):
    """Analyzer specifically for SQLAlchemy patterns."""

    SQLALCHEMY_FUNCTIONS = {
        'text',           # sqlalchemy.text()
        'execute',        # session.execute()
        'exec_driver_sql' # connection.exec_driver_sql()
    }

    def __init__(self, filename: str, source_code: str):
        self.filename = filename
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.vulnerabilities: List[Tuple[int, str, str]] = []

    def analyze(self) -> List[Tuple[int, str, str]]:
        """Run SQLAlchemy-specific analysis."""
        try:
            tree = ast.parse(self.source_code)
            self.visit(tree)
        except SyntaxError as e:
            print(f"Warning: Could not parse {self.filename}: {e}")
        return self.vulnerabilities

    def _get_source_line(self, lineno: int) -> str:
        """Get the source code line."""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _is_sqlalchemy_call(self, node: ast.Call) -> bool:
        """Check if a call is a SQLAlchemy function."""
        func_name = self._get_function_name(node)
        return any(sa_func in func_name for sa_func in self.SQLALCHEMY_FUNCTIONS)

    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""

    def _has_unsafe_string_construction(self, node: ast.AST) -> bool:
        """Check if node uses unsafe string construction."""
        # Check for f-strings
        if isinstance(node, ast.JoinedStr):
            return True

        # Check for string concatenation with +
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True

        # Check for .format()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return True

        # Check for % formatting
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True

        return False

    def _is_safe_bound_parameters(self, node: ast.Call) -> bool:
        """Check if SQLAlchemy call uses bound parameters (safe)."""
        # text("SELECT ... WHERE id = :id") with second argument for params
        if len(node.args) >= 2 or node.keywords:
            # Has parameters passed - likely safe
            return True

        # Check if first argument is text() call with named parameters
        if node.args and isinstance(node.args[0], ast.Call):
            inner_func = self._get_function_name(node.args[0])
            if 'text' in inner_func and node.args[0].args:
                if isinstance(node.args[0].args[0], ast.Constant):
                    query = node.args[0].args[0].value
                    if isinstance(query, str) and ':' in query:
                        # Has named parameters like :id
                        return True

        return False

    def visit_Call(self, node: ast.Call):
        """Check SQLAlchemy calls for unsafe patterns."""
        if self._is_sqlalchemy_call(node):
            # Check if this uses safe bound parameters
            if self._is_safe_bound_parameters(node):
                self.generic_visit(node)
                return

            # Check arguments for unsafe string construction
            for arg in node.args:
                if self._has_unsafe_string_construction(arg):
                    code_line = self._get_source_line(node.lineno)
                    func_name = self._get_function_name(node)
                    self.vulnerabilities.append((
                        node.lineno,
                        code_line,
                        f"SQLAlchemy {func_name}() with unsafe string construction"
                    ))
                    break

                # Check nested text() calls
                if isinstance(arg, ast.Call):
                    inner_func = self._get_function_name(arg)
                    if 'text' in inner_func and arg.args:
                        if self._has_unsafe_string_construction(arg.args[0]):
                            code_line = self._get_source_line(node.lineno)
                            self.vulnerabilities.append((
                                node.lineno,
                                code_line,
                                "SQLAlchemy text() with unsafe string construction"
                            ))
                            break

        self.generic_visit(node)
