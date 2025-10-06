from llm_fuzz.fuzzer import _execute_test_case
from llm_fuzz.fuzzer_agent import TestCase


def test_execute_passing_test(simple_wrapper):
    test_case = TestCase(
        vulnerability_id="vuln_1",
        test_name="test_positive",
        test_input={"x": 5},
        expected_assertion="Should return double the input",
        assertion_code="assert response == 10",
        explanation="Test positive input",
    )
    
    result = _execute_test_case(simple_wrapper, test_case)
    assert result.passed is True
    assert result.response == "10"


def test_execute_with_exception(simple_wrapper):
    test_case = TestCase(
        vulnerability_id="vuln_1",
        test_name="test_negative",
        test_input={"x": -5},
        expected_assertion="Should handle negative input",
        assertion_code="assert has_exception",
        explanation="Test negative input",
    )
    
    result = _execute_test_case(simple_wrapper, test_case)
    assert result.passed is True


def test_execute_complex_assertion(simple_wrapper):
    test_case = TestCase(
        vulnerability_id="vuln_1",
        test_name="test_complex",
        test_input={"x": 3},
        expected_assertion="Response should be positive and even",
        assertion_code="assert isinstance(response, int) and response > 0",
        explanation="Test complex condition",
    )
    
    result = _execute_test_case(simple_wrapper, test_case)
    assert result.passed is True