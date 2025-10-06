import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .fuzzer_agent import FuzzerAgent, TestCase, Vulnerability


@dataclass
class FuzzConfig:
    model: str = "gemini/gemini-2.5-flash"
    max_vulnerabilities: int = 5
    tests_per_vulnerability: int = 3
    max_discovery_steps: int = 15
    temperature: float = 0.1
    verbose: bool = False


@dataclass
class TestResult:
    test_name: str
    vulnerability_id: str
    vulnerability_explanation: str
    input_value: Dict[str, Any]
    passed: bool
    response: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    assertion_result: Optional[str] = None
    assertion_code_executed: Optional[str] = None


@dataclass
class FuzzReport:
    total_count: int = 0
    passed_count: int = 0
    failed_count: int = 0
    total_time: float = 0.0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    results: List[TestResult] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        if self.total_count == 0:
            return 0.0
        return (self.passed_count / self.total_count) * 100

    def save_to_file(self, filepath: Optional[str] = None):
        """Save report as JSON."""
        if filepath is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"llm_fuzz_report_{timestamp}.json"

        data = {
            "summary": {
                "total_count": self.total_count,
                "passed_count": self.passed_count,
                "failed_count": self.failed_count,
                "pass_rate": self.pass_rate,
                "total_time": self.total_time,
                "timestamp": datetime.now().isoformat(),
            },
            "vulnerabilities": [asdict(vuln) for vuln in self.vulnerabilities],
            "results": [asdict(result) for result in self.results],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return filepath


def llm_fuzz(
    target_function: Callable,
    test_function: Callable,
    function_description: Optional[str] = None,
    config: Optional[FuzzConfig] = None,
    custom_test_cases: Optional[List[Dict[str, Any]]] = None,
    fuzz_params: Optional[List[str]] = None,
) -> FuzzReport:
    """
    Args:
        target_function: target function to analyze and test
        test_function: function that executes the target function with test inputs
        function_description: Optional description providing context about the target function
        config: Fuzzer configuration
        custom_test_cases: Additional custom test cases to run
        fuzz_params: List of parameter names to fuzz. If None, all parameters are fuzzed.

    Returns:
        Complete fuzzing report with vulnerabilities and test results
    """
    config = config or FuzzConfig()
    custom_test_cases = custom_test_cases or []

    start_time = time.time()

    fuzzer_agent = FuzzerAgent(
        target_function=target_function,
        fuzz_params=fuzz_params,
        function_description=function_description,
        model=config.model,
        temperature=config.temperature,
        max_discovery_steps=config.max_discovery_steps,
        verbose=config.verbose,
    )

    report = FuzzReport()

    print(
        f"Step 1: Vulnerability discovery for function {target_function.__name__} on parameters {fuzz_params}..."
    )

    vulnerabilities = fuzzer_agent.discover_vulnerabilities(
        max_vulnerabilities=config.max_vulnerabilities
    )
    report.vulnerabilities = vulnerabilities

    if config.verbose:
        print(f"Vulnerabilities discovered: {len(vulnerabilities)}")
        for vuln in vulnerabilities:
            print(f"  - {vuln.name}")

    print("Step 2: Test cases generation...")

    generated_test_cases = fuzzer_agent.generate_test_cases(
        vulnerabilities,
        tests_per_vulnerability=config.tests_per_vulnerability,
    )

    print(f"Test cases generated: {len(generated_test_cases)}")
    print("Step 3: Test cases execution...")

    all_test_cases = []

    if custom_test_cases:
        if config.verbose:
            print(f"Adding {len(custom_test_cases)} custom test cases")
        for i, custom_test in enumerate(custom_test_cases):
            test_case = TestCase(
                vulnerability_id=f"custom_{i + 1}",
                test_name=custom_test.get("test_name", f"custom_test_{i + 1}"),
                test_input=custom_test.get("test_input", {}),
                expected_assertion=custom_test.get("expected_assertion", ""),
                assertion_code=custom_test.get("assertion_code", ""),
                explanation=custom_test.get("explanation", "Custom test"),
            )
            all_test_cases.append(test_case)

    all_test_cases.extend(generated_test_cases)
    report.total_count = len(all_test_cases)

    if config.verbose:
        print(f"Running {len(all_test_cases)} tests")
        print(f"  - Custom tests: {len(custom_test_cases)}")
        print(f"  - Generated tests: {len(all_test_cases) - len(custom_test_cases)}")

    for i, test_case in enumerate(all_test_cases):
        if config.verbose:
            print(f"Test {i + 1}/{len(all_test_cases)}: {test_case.test_name}")

        test_start_time = time.time()

        test_result = _execute_test_case(test_function, test_case)
        test_result.execution_time = time.time() - test_start_time

        if test_result.passed:
            report.passed_count += 1
        else:
            report.failed_count += 1

        report.results.append(test_result)

    report.total_time = time.time() - start_time

    print(
        f"Summary: {report.passed_count}/{report.total_count} tests passed ({report.pass_rate:.1f}%)"
    )
    print(f"Total time: {report.total_time:.2f}s")

    return report


def _execute_test_case(test_function: Callable, test_case: TestCase) -> TestResult:
    """Execute a single test input and evaluate its assertion."""
    result = TestResult(
        test_name=test_case.test_name,
        vulnerability_id=test_case.vulnerability_id,
        vulnerability_explanation=test_case.explanation,
        input_value=test_case.test_input,
        passed=True,
    )

    response = None
    exception_raised = None

    try:
        response = test_function(test_case.test_input)
        result.response = str(response) if response is not None else None
    except Exception as e:
        exception_raised = e
        result.response = None

    context = {
        "response": response,
        "input_data": test_case.test_input,
        "has_exception": exception_raised is not None,
        "no_exception": exception_raised is None,
    }

    try:
        assertion_code = test_case.assertion_code.strip()

        if not assertion_code.startswith("assert "):
            assertion_code = f"assert {assertion_code}"

        exec_globals: Dict[str, Any] = {
            "__builtins__": {
                "any": any,
                "all": all,
                "len": len,
                "isinstance": isinstance,
                "str": str,
                "int": int,
                "float": float,
                "bool": bool,
                "list": list,
                "dict": dict,
                "tuple": tuple,
            }
        }
        exec_globals.update(context)
        exec(assertion_code, exec_globals)

        result.assertion_code_executed = assertion_code
        result.assertion_result = "Assertion passed"
        result.passed = True

    except AssertionError:
        result.passed = False
        result.assertion_result = "Assertion failed"
        result.error = (
            str(exception_raised)
            if exception_raised
            else f"Test failed: {test_case.explanation}"
        )
        result.assertion_code_executed = assertion_code

    except Exception as e:
        result.passed = False
        result.assertion_result = f"Error executing assertion: {str(e)}"
        result.error = f"Invalid assertion: {test_case.assertion_code}"
        result.assertion_code_executed = assertion_code

    return result
