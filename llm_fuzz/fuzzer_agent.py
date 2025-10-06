import json
import re
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Callable, Dict, List, Optional

from smolagents import LiteLLMModel, ToolCallingAgent

from .code_navigation import (
    analyze_parameter_usage,
    extract_function_calls,
    find_definition,
    get_code_navigation_tools,
    get_dependencies,
    get_target_function_file,
)
from .prompts import (
    build_inputs_generation_prompt,
    build_system_prompt,
    build_vulnerability_analysis_prompt,
)


@dataclass
class Vulnerability:
    id: str
    name: str
    description: str
    file_path: str
    function_name: str
    line_numbers: List[int]
    explanation: str


@dataclass
class TestCase:
    vulnerability_id: str
    test_name: str
    test_input: Dict[str, Any]
    expected_assertion: str
    assertion_code: str
    explanation: str


def clean_json_text(text: str) -> str:
    text = text.strip()

    # Remove potential markdown code blocks
    if text.startswith("```"):
        lines = text.split("\n")
        text = (
            "\n".join(lines[1:-1])
            if lines[-1].strip() == "```"
            else "\n".join(lines[1:])
        )

    # Extract JSON if there's extra text
    json_match = re.search(r"\{.*", text, re.DOTALL)
    if json_match:
        text = json_match.group()

    return text


class FuzzerAgent:
    def __init__(
        self,
        target_function: Callable,
        fuzz_params: Optional[List[str]] = None,
        function_description: Optional[str] = None,
        model: str = "gemini/gemini-2.5-flash",
        temperature: float = 0.1,
        max_discovery_steps: int = 15,
        verbose: bool = False,
    ):
        self.target_function = target_function
        self.function_name = getattr(target_function, "__name__", str(target_function))
        self.fuzz_params = fuzz_params or []
        self.function_description = function_description
        self.model_id = model
        self.temperature = temperature

        target_file = get_target_function_file(self.target_function)
        if target_file is None:
            raise ValueError(
                f"Could not find source file for function {self.function_name}"
            )
        self.target_file: str = target_file
        self.dependencies = get_dependencies(self.target_file, self.function_name)

        self.tools = get_code_navigation_tools()
        available_tools = [
            f"{tool.name}({', '.join([f'{k}' for k in tool.inputs.keys()])})"
            for tool in self.tools
        ]
        system_prompt = build_system_prompt(available_tools)

        model_obj = LiteLLMModel(model_id=self.model_id, temperature=self.temperature)
        self.agent = ToolCallingAgent(
            tools=self.tools,
            model=model_obj,
            max_steps=max_discovery_steps,
            instructions=system_prompt,
            verbosity_level=0 if not verbose else 1,
        )

    @cached_property
    def get_target_function_analysis(self) -> Dict[str, Any]:
        function_info = find_definition(
            self.target_file, self.function_name, "function"
        )

        params_to_check = self.fuzz_params if self.fuzz_params else ["message"]
        params_detail = {}

        for param in params_to_check:
            usage = analyze_parameter_usage(self.target_file, self.function_name, param)
            params_detail[param] = usage

        function_calls = extract_function_calls(self.target_file, self.function_name)

        return {
            "file": self.target_file,
            "function": self.function_name,
            "function_info": function_info,
            "params": params_detail,
            "function_calls": function_calls,
            "dependencies": self.dependencies,
        }

    def discover_vulnerabilities(
        self, max_vulnerabilities: int = 5
    ) -> List[Vulnerability]:
        code_analysis_prompt = build_vulnerability_analysis_prompt(
            target_function=self.function_name,
            function_description=self.function_description,
            target_files=[self.target_file],
            dependency_files=self.dependencies.get("files", []),
            fuzz_params=self.fuzz_params,
            max_vulnerabilities=max_vulnerabilities,
        )

        code_analysis_result = self.agent.run(code_analysis_prompt)

        code_analysis_text = self.get_response_text(code_analysis_result)
        vulnerabilities = self.get_vulnerabilities(code_analysis_text)
        return vulnerabilities

    def generate_test_cases(
        self, vulnerabilities: List[Vulnerability], tests_per_vulnerability: int = 3
    ) -> List[TestCase]:
        """Generate test cases for discovered vulnerabilities."""
        test_cases = []

        for vulnerability in vulnerabilities:
            test_prompt = build_inputs_generation_prompt(
                vulnerability=vulnerability,
                target_function=self.function_name,
                function_description=self.function_description,
                code_analysis_summary=json.dumps(self.get_target_function_analysis),
                fuzz_params=self.fuzz_params,
                num_tests=tests_per_vulnerability,
            )

            gen_model = LiteLLMModel(
                model_id=self.model_id, temperature=self.temperature
            )
            response = gen_model([{"role": "user", "content": test_prompt}])
            json_text = self.get_response_text(response)

            test_cases.extend(self.get_tests_cases(json_text, vulnerability))

        return test_cases

    def get_response_text(self, response) -> str:
        """Get text content from LLM response in various formats."""
        if hasattr(response, "text"):
            return response.text
        elif hasattr(response, "content"):
            return response.content
        return str(response)

    def get_vulnerabilities(self, analysis_text: str) -> List[Vulnerability]:
        """Get vulnerability data from JSON response text."""
        json_text = clean_json_text(analysis_text)
        vulnerabilities_data = json.loads(json_text)

        if "vulnerabilities" in vulnerabilities_data:
            vuln_list = vulnerabilities_data["vulnerabilities"]
        else:
            vuln_list = vulnerabilities_data

        vulnerabilities = []
        for i, vuln_data in enumerate(vuln_list):
            vulnerabilities.append(
                Vulnerability(
                    id=vuln_data.get("id", f"vuln_{i + 1}"),
                    name=vuln_data.get("name", "Unknown Vulnerability"),
                    description=vuln_data.get("description", ""),
                    file_path=vuln_data.get("file_path", ""),
                    function_name=vuln_data.get("function_name", self.function_name),
                    line_numbers=vuln_data.get("line_numbers", []),
                    explanation=vuln_data.get("explanation", ""),
                )
            )

        return vulnerabilities

    def get_tests_cases(
        self, json_text: str, vulnerability: Vulnerability
    ) -> List[TestCase]:
        """Get test input data from JSON response text."""
        cleaned_text = clean_json_text(json_text)
        test_data = json.loads(cleaned_text)

        if isinstance(test_data, dict) and isinstance(test_data.get("tests"), list):
            proposed_tests = test_data["tests"]
        else:
            proposed_tests = [test_data]

        test_cases = []
        for test_dict in proposed_tests:
            # safety: only keep params that are in the fuzz_params list
            if self.fuzz_params and isinstance(test_dict.get("test_input"), dict):
                test_dict["test_input"] = {
                    k: v
                    for k, v in test_dict["test_input"].items()
                    if k in self.fuzz_params
                }

            test_case = TestCase(
                vulnerability_id=test_dict.get("vulnerability_id", vulnerability.id),
                test_name=test_dict.get("test_name", f"test_{vulnerability.id}"),
                test_input=test_dict.get("test_input", {}),
                expected_assertion=test_dict.get("expected_assertion", ""),
                assertion_code=test_dict.get("assertion_code", ""),
                explanation=test_dict.get("explanation", ""),
            )
            test_cases.append(test_case)

        return test_cases
