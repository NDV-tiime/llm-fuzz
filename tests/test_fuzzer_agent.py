from llm_fuzz.fuzzer_agent import Vulnerability


def test_get_vulnerabilities_parsing():
    from llm_fuzz.fuzzer_agent import FuzzerAgent
    
    agent = object.__new__(FuzzerAgent)
    agent.function_name = "test_function"
    
    json_text = """
    {
      "vulnerabilities": [
        {
          "id": "vuln_001",
          "name": "Test Vulnerability",
          "description": "A test vulnerability",
          "file_path": "/path/to/file.py",
          "function_name": "test_function",
          "line_numbers": [10, 11],
          "explanation": "Test explanation"
        }
      ]
    }
    """
    
    vulnerabilities = agent.get_vulnerabilities(json_text)
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].id == "vuln_001"


def test_get_test_cases_filters_params():
    from llm_fuzz.fuzzer_agent import FuzzerAgent
    
    agent = object.__new__(FuzzerAgent)
    agent.fuzz_params = ["x"]
    
    vuln = Vulnerability(
        id="vuln_001",
        name="Test",
        description="Test",
        file_path="test.py",
        function_name="test",
        line_numbers=[1],
        explanation="Test",
    )
    
    json_text = """
    {
      "tests": [
        {
          "vulnerability_id": "vuln_001",
          "test_name": "test_1",
          "test_input": {"x": 1, "y": 2, "z": 3},
          "expected_assertion": "Should work",
          "assertion_code": "assert True",
          "explanation": "Test"
        }
      ]
    }
    """
    
    test_cases = agent.get_tests_cases(json_text, vuln)
    assert "x" in test_cases[0].test_input
    assert "y" not in test_cases[0].test_input