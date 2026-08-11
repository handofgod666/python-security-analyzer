import ast
from typing import Set, Dict, List, Optional, Tuple
from enum import Enum


class TaintSource(Enum):
    """Categories of data sources."""
    USER_INPUT = "user_input"  # request.args, input(), etc.
    DATABASE = "database"      # cursor.fetchall(), etc.
    FILE = "file"              # open(), read(), etc.
    NETWORK = "network"        # requests.get(), etc.
    SAFE = "safe"              # hardcoded strings, config
    UNKNOWN = "unknown"        # can't determine


class TaintedVariable:
    """Represents a variable that may contain tainted data."""

    def __init__(self, name: str, source: TaintSource, lineno: int, context: str = ""):
        self.name = name
        self.source = source
        self.lineno = lineno
        self.context = context

    def __repr__(self):
        return f"TaintedVariable({self.name}, {self.source.value}, line {self.lineno})"


class DataFlowAnalyzer(ast.NodeVisitor):
    """Tracks data flow to identify tainted variables in SQL contexts."""

    # Known sources of user input
    USER_INPUT_SOURCES = {
        'input', 'raw_input',
        # Flask/Django
        'request.args', 'request.form', 'request.json', 'request.data',
        'request.GET', 'request.POST', 'request.FILES',
        # FastAPI
        'Query', 'Path', 'Body', 'Form',
    }

    # Database read operations (generally safe to use in queries)
    DATABASE_SOURCES = {
        'fetchone', 'fetchall', 'fetchmany',
        'execute', 'executemany',
    }

    # File operations
    FILE_SOURCES = {
        'read', 'readline', 'readlines',
        'open',
    }

    # Network operations
    NETWORK_SOURCES = {
        'get', 'post', 'put', 'delete',
        'urlopen', 'urlretrieve',
    }

    def __init__(self, filename: str, source_code: str):
        self.filename = filename
        self.source_code = source_code
        self.source_lines = source_code.splitlines()

        # Track tainted variables by scope
        self.tainted_vars: Dict[str, TaintedVariable] = {}

        # Track SQL-related calls with tainted variables
        self.tainted_sql_uses: List[Tuple[int, str, TaintedVariable]] = []

    def analyze(self) -> List[Tuple[int, str, TaintedVariable]]:
        """Run data flow analysis."""
        try:
            tree = ast.parse(self.source_code)
            self.visit(tree)
        except SyntaxError as e:
            print(f"Warning: Could not parse {self.filename}: {e}")
        return self.tainted_sql_uses

    def _get_source_line(self, lineno: int) -> str:
        """Get the source code line."""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _identify_taint_source(self, node: ast.AST) -> Optional[TaintSource]:
        """Identify if a node represents a tainted data source."""

        # Check for function calls
        if isinstance(node, ast.Call):
            func_name = self._get_function_name(node)

            if any(src in func_name for src in self.USER_INPUT_SOURCES):
                return TaintSource.USER_INPUT
            elif any(src in func_name for src in self.DATABASE_SOURCES):
                return TaintSource.DATABASE
            elif any(src in func_name for src in self.FILE_SOURCES):
                return TaintSource.FILE
            elif any(src in func_name for src in self.NETWORK_SOURCES):
                return TaintSource.NETWORK

        # Check for attribute access (e.g., request.args['user'])
        if isinstance(node, ast.Attribute) or isinstance(node, ast.Subscript):
            node_str = ast.unparse(node) if hasattr(ast, 'unparse') else ""
            if any(src in node_str for src in self.USER_INPUT_SOURCES):
                return TaintSource.USER_INPUT

        # Constants are safe
        if isinstance(node, ast.Constant):
            return TaintSource.SAFE

        return None

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

    def _get_name_from_node(self, node: ast.AST) -> Optional[str]:
        """Extract variable name from various node types."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return ast.unparse(node) if hasattr(ast, 'unparse') else None
        return None

    def _is_tainted(self, node: ast.AST) -> Optional[TaintedVariable]:
        """Check if a node uses a tainted variable."""

        # Direct variable reference
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return self.tainted_vars[node.id]

        # Check all Name nodes in the expression
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                return self.tainted_vars[child.id]

        return None

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments."""
        # Check if the value being assigned is from a tainted source
        taint_source = self._identify_taint_source(node.value)

        # Or if it uses a tainted variable
        tainted_var = self._is_tainted(node.value)

        if taint_source or tainted_var:
            source = taint_source if taint_source else tainted_var.source
            code_line = self._get_source_line(node.lineno)

            # Mark all assigned variables as tainted
            for target in node.targets:
                var_name = self._get_name_from_node(target)
                if var_name:
                    self.tainted_vars[var_name] = TaintedVariable(
                        name=var_name,
                        source=source,
                        lineno=node.lineno,
                        context=code_line
                    )

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Track annotated assignments (e.g., user_id: str = input())."""
        if node.value:
            taint_source = self._identify_taint_source(node.value)
            tainted_var = self._is_tainted(node.value)

            if taint_source or tainted_var:
                source = taint_source if taint_source else tainted_var.source
                var_name = self._get_name_from_node(node.target)
                if var_name:
                    code_line = self._get_source_line(node.lineno)
                    self.tainted_vars[var_name] = TaintedVariable(
                        name=var_name,
                        source=source,
                        lineno=node.lineno,
                        context=code_line
                    )

        self.generic_visit(node)

    def _is_sql_related_call(self, node: ast.Call) -> bool:
        """Check if a function call is SQL-related."""
        func_name = self._get_function_name(node)
        sql_functions = {'execute', 'executemany', 'raw', 'query'}
        return any(sql_func in func_name for sql_func in sql_functions)

    def visit_Call(self, node: ast.Call):
        """Check if tainted data is used in SQL calls."""
        if self._is_sql_related_call(node):
            # Check if this is a parameterized query (safe usage)
            is_parameterized = self._is_parameterized_query(node)

            if not is_parameterized:
                # Check all arguments for tainted variables
                for arg in node.args:
                    tainted = self._is_tainted(arg)
                    if tainted and tainted.source in [TaintSource.USER_INPUT, TaintSource.FILE, TaintSource.NETWORK]:
                        code_line = self._get_source_line(node.lineno)
                        self.tainted_sql_uses.append((node.lineno, code_line, tainted))

        self.generic_visit(node)

    def _is_parameterized_query(self, node: ast.Call) -> bool:
        """Check if a SQL call uses parameterized queries (safe)."""
        # Parameterized queries have at least 2 arguments: query string and parameters
        if len(node.args) >= 2:
            # First arg should be a constant string
            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                # Check if query string contains placeholders
                query = node.args[0].value
                # Common placeholders: ?, %s, :name, $1
                return any(ph in query for ph in ['?', '%s', '%(', ':'])
        return False

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Check f-strings for tainted variables."""
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                tainted = self._is_tainted(value.value)
                if tainted and tainted.source in [TaintSource.USER_INPUT, TaintSource.FILE, TaintSource.NETWORK]:
                    # Check if this f-string might be SQL
                    code_line = self._get_source_line(node.lineno)
                    if any(keyword in code_line.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
                        self.tainted_sql_uses.append((node.lineno, code_line, tainted))

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        """Check string concatenation for tainted variables."""
        if isinstance(node.op, ast.Add):
            tainted = self._is_tainted(node)
            if tainted and tainted.source in [TaintSource.USER_INPUT, TaintSource.FILE, TaintSource.NETWORK]:
                code_line = self._get_source_line(node.lineno)
                if any(keyword in code_line.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
                    self.tainted_sql_uses.append((node.lineno, code_line, tainted))

        self.generic_visit(node)
