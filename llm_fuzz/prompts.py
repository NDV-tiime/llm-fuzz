def build_system_prompt(available_tools):
    tools_section = (
        "\n".join(f"- {tool}" for tool in available_tools)
        if available_tools
        else "- (no tools listed)"
    )

    return f"""You are an expert in Python code security and an intelligent fuzzer agent. Act as a malicious user who has access to the target function's source code and its dependencies.

Your goals: analyze the target function to discover vulnerabilities.

Available tools:
{tools_section}

Approach:
1) Start reading the function code file, to understand the function and its parameters
2) Trace input dataflow ONLY for the target parameters specified for fuzzing
3) When relevant, identify and explore imported functions, classes, or variables used by the target function using the available tools
4) Prioritize critical vulnerabilities and real exploit paths that are reachable through the target parameters

Guidance:
- You can explore any file, function, or variable related to the target
- Use tools strategically to locate vulnerabilities in the target parameters' data flow
- Focus exclusively on how the specified fuzz parameters can be exploited
"""


def build_vulnerability_analysis_prompt(
    *,
    target_function: str,
    function_description: str | None,
    target_files: list[str],
    dependency_files: list[str] | None,
    fuzz_params: list[str] | None,
    max_vulnerabilities: int = 5,
):
    files_block = "\n".join(f"- {p}" for p in (target_files or [])) or "- (none)"
    deps_block = (
        "\n".join(f"- {p}" for p in (dependency_files or []))
        if dependency_files
        else "- (none)"
    )
    params_block = (
        "\n".join(f"- {p}" for p in (fuzz_params or []))
        if fuzz_params
        else "- All parameters"
    )
    context_block = (
        f"\nFUNCTION CONTEXT:\n{function_description}\n" if function_description else ""
    )

    return f"""VULNERABILITY ANALYSIS

TARGET FUNCTION: {target_function}
{context_block}
TARGET FILES:
{files_block}

RELATED FILES (if helpful to identify vulnerabilities):
{deps_block}

TARGET PARAMETERS FOR FUZZING:
{params_block}

TASK:
- Analyze the target function and its code
- Explore the code of functions, variables, and classes that are called by the target function or on which the target function depends, if relevant to identify vulnerabilities.
- CRITICAL: Focus ONLY on vulnerabilities that can be exploited through the specified target parameters for fuzzing: {params_block}
- Do NOT report vulnerabilities in other parameters, internal variables, or code paths that cannot be reached through the target parameters
- Focus on how the target parameters are processed and potential weak points in their data flow
- Prioritize critical, realistic vulnerabilities that are directly exploitable through the target parameters
- Find {max_vulnerabilities} vulnerabilities, but can be less if you don't find this many vulnerabilities

REQUIRED OUTPUT (STRICT JSON ONLY, NO EXTRA TEXT):
Return ONLY valid JSON in this exact format. Do not include any markdown, explanations, or other text.

{{
  "vulnerabilities": [
    {{
      "id": "vuln_001",
      "name": "Short vulnerability name",
      "description": "Detailed description",
      "file_path": "path/to/file.py",
      "function_name": "{target_function}",
      "line_numbers": [10, 11],
      "explanation": "Technical explanation based on the code",
    }}
  ]
}}
"""


def build_inputs_generation_prompt(
    vulnerability,
    target_function,
    function_description,
    code_analysis_summary,
    fuzz_params,
    num_tests,
):
    context_block = (
        f"\nFUNCTION CONTEXT:\n{function_description}\n" if function_description else ""
    )
    if fuzz_params:
        constraints = "Only include these parameters in test_input:\n" + "\n".join(
            f"- {p}" for p in fuzz_params
        )
    else:
        constraints = (
            "TEST INPUT CONSTRAINTS: All parameters can be included in test_input."
        )

    return f"""Generate targeted test cases for this vulnerability based on the provided analysis.

VULNERABILITY DETAILS:
- ID: {vulnerability.id}
- Name: {vulnerability.name}
- Description: {vulnerability.description}
- File: {vulnerability.file_path}
- Function: {vulnerability.function_name}
- Lines: {vulnerability.line_numbers}
- Explanation: {vulnerability.explanation}


TARGET FUNCTION: {target_function}
{context_block}

CODE ANALYSIS SUMMARY (JSON):
{code_analysis_summary}

INSTRUCTIONS:
- Generate {num_tests} test case(s) that target this vulnerability
- {constraints}
- Use the code analysis to create realistic malicious inputs that exploit the identified vulnerability
- Favor robust, deterministic assertions over arbitrary content checks
- Avoid brittle keyword assertions on free-form text
- Prefer checking for specific substrings when they are deterministic system messages produced by explicit code paths (e.g., exact error messages)
- When invalid input should be rejected by design, assert has_exception

REQUIRED OUTPUT (STRICT JSON ONLY, NO EXTRA TEXT):
Return ONLY valid JSON. Use ONLY double quotes for strings, never single quotes.
Do not use escape sequences like \' or \" - use plain text instead.
Keep assertion code simple.

{{
  "tests": [
    {{
      "vulnerability_id": "{vulnerability.id}",
      "test_name": "descriptive_test_name",
      "test_input": {{"param": "malicious_value"}},
      "expected_assertion": "What should happen for secure behavior",
      "assertion_code": "assert <condition>",
      "explanation": "How this input exploits the vulnerability",
    }}
  ]
}}

ASSERTION RULES:
- Available variables: response, input_data, has_exception, no_exception
- Assertions should PASS when the system behaves securely (no vulnerability triggered)
- Assertions should FAIL when vulnerabilities are triggered
- Prefer: "assert no_exception and isinstance(response, str) and len(response.strip()) > 0" for text-returning functions
- Use "assert has_exception" for inputs that should be rejected; optionally combine with stable message prefix checks: e.g., response.startswith("Error:")
- Avoid arbitrary keyword checks like "'bad' not in response" unless tied to a deterministic code path documented in the analysis
"""
