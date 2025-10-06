import ast
import inspect
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import jedi
from smolagents import Tool


def get_source_and_script(file_path: str) -> Tuple[str, jedi.Script]:
    """Load source code and create Jedi script for analysis.

    Args:
        file_path: Path to the Python file to analyze.

    Returns:
        Tuple containing source code and Jedi script object.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()
    script = jedi.Script(code=source, path=file_path)
    return source, script


def get_target_function_file(function_obj: Any) -> Optional[str]:
    """Get the file containing a function object.

    Args:
        function_obj: The function object to locate.

    Returns:
        Path to the Python file containing the function, or None if not found.
    """
    if hasattr(function_obj, "__code__") and hasattr(
        function_obj.__code__, "co_filename"
    ):
        file_path = function_obj.__code__.co_filename
        if os.path.exists(file_path) and file_path.endswith(".py"):
            return file_path

    file_path = inspect.getfile(function_obj)
    if os.path.exists(file_path) and file_path.endswith(".py"):
        return file_path

    return None


def get_dependencies(target_file: str, function_name: str) -> Dict[str, Any]:
    """Get dependencies for a function including external files and imports.

    Args:
        target_file: Path to the file containing the target function.
        function_name: Name of the function to analyze.

    Returns:
        Dictionary containing dependency files and imported items.
    """
    source, script = get_source_and_script(target_file)
    tree = ast.parse(source)

    target_func = None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ):
            target_func = node
            break

    if not target_func:
        return {"files": [], "imports": []}

    dependency_files = set()
    imports = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            module_path = node.module.replace(".", "/")
            possible_paths = [f"src/{module_path}.py", f"{module_path}.py"]

            for path in possible_paths:
                if os.path.exists(path):
                    dependency_files.add(path)
                    imports.append(
                        {
                            "module": node.module,
                            "file": path,
                            "names": [alias.name for alias in node.names],
                        }
                    )
                    break

    for node in ast.walk(target_func):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            definitions = script.infer(line=node.lineno, column=node.col_offset)
            for definition in definitions:
                if (
                    definition.module_path
                    and str(definition.module_path) != target_file
                ):
                    dependency_files.add(str(definition.module_path))

    return {"files": list(dependency_files), "imports": imports}


def read_file_content(
    file_path: str, start_line: Optional[int] = None, end_line: Optional[int] = None
) -> str:
    """Read complete file or specific section.

    Args:
        file_path: Path to the Python file to read.
        start_line: Optional starting line number (1-based).
        end_line: Optional ending line number (inclusive).

    Returns:
        The file content or specified section.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        if start_line is None and end_line is None:
            return f.read()

        lines = f.readlines()
        start_idx = max(0, start_line - 1) if start_line else 0
        end_idx = min(len(lines), end_line) if end_line else len(lines)
        return "".join(lines[start_idx:end_idx])


def find_definition(
    file_path: str, name: str, definition_type: str = "function"
) -> Dict[str, Any]:
    """Find function, class, or variable definition with comprehensive information.

    Args:
        file_path: Path to the Python file to search.
        name: Name of the definition to find.
        definition_type: Type of definition ('function', 'class', or 'variable').

    Returns:
        Dictionary with definition details including code, parameters, and location.
    """
    source, script = get_source_and_script(file_path)
    lines = source.split("\n")

    for definition in script.get_names(all_scopes=True, definitions=True):
        if definition.name == name and definition.type == definition_type:
            start_line = definition.line or 1
            end_line = min(start_line + 20, len(lines))

            code_lines = []
            for i in range(start_line - 1, end_line):
                if i < len(lines):
                    code_lines.append(f"{i + 1:4d}| {lines[i]}")

            result = {
                "name": name,
                "type": definition_type,
                "file": file_path,
                "line": start_line,
                "code": "\n".join(code_lines),
                "description": definition.description,
                "found": True,
            }

            if definition_type == "function":
                params = []
                signatures = definition.get_signatures()
                if signatures:
                    for param in signatures[0].params:
                        params.append(
                            {
                                "name": param.name,
                                "description": param.description,
                                "has_default": hasattr(param, "default")
                                and param.default is not None,
                            }
                        )
                result["parameters"] = params
                result["docstring"] = getattr(definition, "docstring", lambda: "")()

            return result

    return {"name": name, "type": definition_type, "file": file_path, "found": False}


def list_file_contents(file_path: str) -> Dict[str, Any]:
    """List all functions, classes, and variables in a file.

    Args:
        file_path: Path to the Python file to analyze.

    Returns:
        Dictionary containing categorized definitions with their names, lines, and types.
    """
    source, script = get_source_and_script(file_path)

    contents: Dict[str, List[Dict[str, Any]]] = {
        "functions": [],
        "classes": [],
        "variables": [],
    }

    for definition in script.get_names(all_scopes=True, definitions=True):
        item = {
            "name": definition.name,
            "line": definition.line,
            "type": definition.type,
        }

        if definition.type == "function":
            contents["functions"].append(item)
        elif definition.type == "class":
            contents["classes"].append(item)
        else:
            contents["variables"].append(item)

    return contents


def analyze_parameter_usage(
    file_path: str, function_name: str, param_name: str
) -> Dict[str, Any]:
    """Analyze how a parameter is used within a function using AST and intelligent inference.

    Args:
        file_path: Path to the Python file containing the function.
        function_name: Name of the function to analyze.
        param_name: Name of the parameter to analyze.

    Returns:
        Dictionary containing parameter usage analysis including comparisons,
        function calls, attribute access, and all lines where the parameter is used.
    """
    source, script = get_source_and_script(file_path)
    tree = ast.parse(source)
    lines = source.split("\n")

    target_func = None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ):
            target_func = node
            break

    if not target_func:
        return {"error": f"Function '{function_name}' not found"}

    usage: Dict[str, Any] = {
        "parameter": param_name,
        "comparisons": [],
        "function_calls": [],
        "attribute_access": [],
        "assignments": [],
        "all_lines": [],
    }

    for node in ast.walk(target_func):
        if isinstance(node, ast.Name) and node.id == param_name:
            line_content = (
                lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
            )
            usage["all_lines"].append({"line": node.lineno, "code": line_content})

            inferred = script.infer(line=node.lineno, column=node.col_offset)
            context = [inf.description for inf in inferred if inf.description]
            if context:
                usage["all_lines"][-1]["context"] = context[0]

        if isinstance(node, ast.Compare):
            if any(
                isinstance(comp, ast.Name) and comp.id == param_name
                for comp in [node.left] + node.comparators
            ):
                usage["comparisons"].append(
                    {
                        "line": node.lineno,
                        "operation": [type(op).__name__ for op in node.ops],
                        "code": lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else "",
                    }
                )

        if isinstance(node, ast.Call):
            if any(
                isinstance(arg, ast.Name) and arg.id == param_name for arg in node.args
            ):
                call_name = "unknown"
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                usage["function_calls"].append(
                    {
                        "line": node.lineno,
                        "function": call_name,
                        "code": lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else "",
                    }
                )

        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == param_name
        ):
            usage["attribute_access"].append(
                {
                    "line": node.lineno,
                    "attribute": node.attr,
                    "code": lines[node.lineno - 1].strip()
                    if node.lineno <= len(lines)
                    else "",
                }
            )

    return usage


def find_code_patterns(file_path: str, pattern: str) -> List[Dict[str, Any]]:
    """Search for specific code patterns in a file.

    Args:
        file_path: Path to the Python file to search.
        pattern: Regular expression pattern to search for.

    Returns:
        List of dictionaries containing line numbers, content, and context
        for each pattern match found.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    matches = []
    for i, line in enumerate(lines):
        if re.search(pattern, line, re.IGNORECASE):
            context_start = max(0, i - 2)
            context_end = min(len(lines), i + 3)

            context_lines = []
            for j in range(context_start, context_end):
                marker = " >>>" if j == i else "    "
                context_lines.append(f"{j + 1:4d}{marker} {lines[j].rstrip()}")

            matches.append(
                {
                    "line": i + 1,
                    "content": line.strip(),
                    "context": "\n".join(context_lines),
                }
            )

    return matches


def extract_function_calls(file_path: str, function_name: str) -> List[Dict[str, Any]]:
    """Extract all function calls within a specific function.

    Args:
        file_path: Path to the Python file containing the function.
        function_name: Name of the function to analyze.

    Returns:
        List of dictionaries containing information about each function call found.
    """
    source, script = get_source_and_script(file_path)
    tree = ast.parse(source)

    target_func = None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ):
            target_func = node
            break

    if not target_func:
        return []

    calls: List[Dict[str, Any]] = []
    for node in ast.walk(target_func):
        if isinstance(node, ast.Call):
            call_info: Dict[str, Any] = {"line": node.lineno, "arguments": []}

            if isinstance(node.func, ast.Name):
                call_info["name"] = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    call_info["name"] = f"{node.func.value.id}.{node.func.attr}"
                else:
                    call_info["name"] = f"?.{node.func.attr}"
            else:
                call_info["name"] = "unknown"

            for arg in node.args:
                if isinstance(arg, ast.Constant):
                    call_info["arguments"].append(repr(arg.value))
                elif isinstance(arg, ast.Name):
                    call_info["arguments"].append(arg.id)
                else:
                    call_info["arguments"].append(type(arg).__name__)

            calls.append(call_info)

    return calls


class ReadFileTool(Tool):
    name = "read_file"
    description = "Read complete file or specific section"
    inputs = {
        "file_path": {"type": "string", "description": "Path to the source file"},
        "start_line": {
            "type": "integer",
            "optional": True,
            "nullable": True,
            "description": "Start line (1-based), optional",
        },
        "end_line": {
            "type": "integer",
            "optional": True,
            "nullable": True,
            "description": "End line (inclusive), optional",
        },
    }
    output_type = "string"

    def forward(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        return read_file_content(file_path, start_line, end_line)


class FindDefinitionTool(Tool):
    name = "find_definition"
    description = "Find function, class, or variable definition with code and context"
    inputs = {
        "file_path": {"type": "string", "description": "Path to the source file"},
        "name": {"type": "string", "description": "Name to find"},
        "definition_type": {
            "type": "string",
            "optional": True,
            "nullable": True,
            "description": "Type: 'function', 'class', or 'variable' (default: function)",
        },
    }
    output_type = "object"

    def forward(
        self, file_path: str, name: str, definition_type: str = "function"
    ) -> Dict[str, Any]:
        return find_definition(file_path, name, definition_type or "function")


class AnalyzeParameterTool(Tool):
    name = "analyze_parameter"
    description = "Analyze how a parameter is used within a function"
    inputs = {
        "file_path": {"type": "string", "description": "Path to the source file"},
        "function_name": {"type": "string", "description": "Function name to analyze"},
        "param_name": {"type": "string", "description": "Parameter name to analyze"},
    }
    output_type = "object"

    def forward(
        self, file_path: str, function_name: str, param_name: str
    ) -> Dict[str, Any]:
        return analyze_parameter_usage(file_path, function_name, param_name)


class FindPatternsTool(Tool):
    name = "find_patterns"
    description = "Search for specific code patterns or keywords in a file"
    inputs = {
        "file_path": {"type": "string", "description": "Path to the source file"},
        "pattern": {
            "type": "string",
            "description": "Pattern or keyword to search for",
        },
    }
    output_type = "object"

    def forward(self, file_path: str, pattern: str) -> List[Dict[str, Any]]:
        return find_code_patterns(file_path, pattern)


class ListFileContentsTool(Tool):
    name = "list_file_contents"
    description = "List all functions, classes, and variables in a file"
    inputs = {
        "file_path": {"type": "string", "description": "Path to the source file"},
    }
    output_type = "object"

    def forward(self, file_path: str) -> Dict[str, Any]:
        return list_file_contents(file_path)


def get_code_navigation_tools() -> List[Tool]:
    return [
        ReadFileTool(),
        FindDefinitionTool(),
        AnalyzeParameterTool(),
        FindPatternsTool(),
        ListFileContentsTool(),
    ]
