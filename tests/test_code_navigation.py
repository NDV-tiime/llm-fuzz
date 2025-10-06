import pytest

from llm_fuzz.code_navigation import (
    find_definition,
    get_target_function_file,
    read_file_content,
)


@pytest.fixture
def sample_python_file(tmp_path):
    """Create a sample Python file for testing."""
    code = '''
def sample_function(x, y):
    if x < 0:
        raise ValueError("Negative x not allowed")
    return x + y

def helper_function(value):
    return value * 2

class SampleClass:
    def method(self):
        return "test"
'''
    file_path = tmp_path / "sample.py"
    file_path.write_text(code)
    return str(file_path)


def test_get_target_function_file():
    def test_func():
        return 42
    
    file_path = get_target_function_file(test_func)
    assert file_path is not None
    assert file_path.endswith(".py")


def test_read_full_file(sample_python_file):
    content = read_file_content(sample_python_file)
    assert "def sample_function" in content
    assert "def helper_function" in content


def test_find_function(sample_python_file):
    result = find_definition(sample_python_file, "sample_function", "function")
    assert result["found"] is True
    assert result["name"] == "sample_function"


def test_find_nonexistent(sample_python_file):
    result = find_definition(sample_python_file, "nonexistent", "function")
    assert result["found"] is False