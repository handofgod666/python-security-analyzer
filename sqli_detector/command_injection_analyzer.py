import ast
from typing import List, Tuple, Set
from .dataflow import DataFlowAnalyzer, TaintedVariable


class CommandInjectionAnalyzer(ast.NodeVisitor):
    """Analyzer for detecting command injection vulnerabilities."""

    # Dangerous functions that execute shell commands
    DANGEROUS_FUNCTIONS = {
        'os.system', 'os.popen', 'os.spawn', 'os.spawnl', 'os.spawnle',
        'os.spawnlp', 'os.spawnlpe', 'os.spawnv', 'os.spawnve',
        'os.spawnvp', 'os.spawnvpe',
        'subprocess.call', 'subprocess.run', 'subprocess.Popen',
        'subprocess.check_call', 'subprocess.check_output',
        'commands.getoutput', 'commands.getstatusoutput',
        'popen2.popen2', 'popen2.popen3', 'popen2.popen4'
    }

    def __init__(self, filename: str, source_code: str):
        self.filename = filename
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.vulnerabilities: List[Tuple[int, str, str]] = []
        self.tainted_vars: Set[str] = set()
        self.imports: Set[str] = set()

    def analyze(self) -> List[Tuple[int, str, str]]:
        """Run the analysis on the source code."""
        try:
            tree = ast.parse(self.source_code)

            # First pass: collect tainted variables
            df_analyzer = DataFlowAnalyzer(self.filename, self.source_code)
            tainted_uses = df_analyzer.analyze()

            for _, _, tainted_var in tainted_uses:
                self.tainted_vars.add(tainted_var.name)

            # Also track simple assignments from input() directly
            self._track_assignments(tree)

            # Second pass: find command injection vulnerabilities
            self.visit(tree)
        except SyntaxError:
            pass

        return self.vulnerabilities

    def _track_assignments(self, tree: ast.AST):
        """Track simple variable assignments from user input sources."""
        # Multiple passes to propagate taint through assignments
        changed = True
        max_iterations = 10
        iteration = 0

        while changed and iteration < max_iterations:
            changed = False
            iteration += 1

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    # Check if right side is input() or similar
                    if isinstance(node.value, ast.Call):
                        func_name = self._get_function_name(node.value)
                        if func_name in ('input', 'raw_input'):
                            # Mark all targets as tainted
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    if target.id not in self.tainted_vars:
                                        self.tainted_vars.add(target.id)
                                        changed = True

                        # Check if .format() is called with tainted args
                        if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'format':
                            for arg in node.value.args:
                                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                                    # Result of .format() with tainted arg is tainted
                                    for target in node.targets:
                                        if isinstance(target, ast.Name):
                                            if target.id not in self.tainted_vars:
                                                self.tainted_vars.add(target.id)
                                                changed = True

                    # Check if assigned from another tainted variable
                    elif isinstance(node.value, ast.Name):
                        if node.value.id in self.tainted_vars:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    if target.id not in self.tainted_vars:
                                        self.tainted_vars.add(target.id)
                                        changed = True

    def _get_source_line(self, lineno: int) -> str:
        """Get the source code line."""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _get_function_name(self, node: ast.Call) -> str:
        """Extract full function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ""

    def _contains_tainted_data(self, node: ast.AST) -> bool:
        """Check if a node contains tainted variables."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.JoinedStr):
            # f-string with tainted variables
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if self._contains_tainted_data(value.value):
                        return True
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # String concatenation with tainted data
            return (self._contains_tainted_data(node.left) or
                    self._contains_tainted_data(node.right))
        elif isinstance(node, ast.Call):
            # .format() or other calls with tainted args
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                for arg in node.args:
                    if self._contains_tainted_data(arg):
                        return True
        return False

    def _is_safe_subprocess_call(self, node: ast.Call) -> bool:
        """Check if subprocess call uses safe list format."""
        func_name = self._get_function_name(node)

        if not func_name.startswith('subprocess.'):
            return False

        # Check if first argument is a list (safe)
        if node.args and isinstance(node.args[0], ast.List):
            # Also check that shell is not True
            for keyword in node.keywords:
                if keyword.arg == 'shell':
                    if isinstance(keyword.value, ast.Constant):
                        if keyword.value.value is True:
                            return False
            return True

        return False

    def visit_Import(self, node: ast.Import):
        """Track imported modules."""
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from X import Y statements."""
        if node.module:
            for alias in node.names:
                self.imports.add(f"{node.module}.{alias.name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Detect dangerous function calls with user input."""
        func_name = self._get_function_name(node)

        # Check for eval() and exec() - always dangerous with user input
        if func_name in ('eval', 'exec'):
            if node.args:
                if self._contains_tainted_data(node.args[0]):
                    code_line = self._get_source_line(node.lineno)
                    vuln_type = f"Command injection via {func_name}"
                    self.vulnerabilities.append((node.lineno, code_line, vuln_type))
            self.generic_visit(node)
            return

        # Check if it's a dangerous function
        if func_name in self.DANGEROUS_FUNCTIONS:
            # Check if it's a safe subprocess call
            if self._is_safe_subprocess_call(node):
                self.generic_visit(node)
                return

            # Check arguments for tainted data
            has_tainted = False
            for arg in node.args:
                if self._contains_tainted_data(arg):
                    has_tainted = True
                    break

                # Check for f-strings or string concatenation
                if isinstance(arg, ast.JoinedStr):
                    has_tainted = True
                    break
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    has_tainted = True
                    break

            if has_tainted:
                code_line = self._get_source_line(node.lineno)

                # Check if shell=True is used
                shell_enabled = False
                for keyword in node.keywords:
                    if keyword.arg == 'shell':
                        if isinstance(keyword.value, ast.Constant):
                            shell_enabled = keyword.value.value is True

                if shell_enabled and func_name.startswith('subprocess.'):
                    vuln_type = "Command injection via subprocess with shell=True"
                else:
                    vuln_type = f"Command injection via {func_name}"

                self.vulnerabilities.append((node.lineno, code_line, vuln_type))

        self.generic_visit(node)
