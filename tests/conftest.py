import pytest


@pytest.fixture
def simple_function():
    """A simple function for testing."""
    def func(x: int) -> int:
        if x < 0:
            raise ValueError("Negative values not allowed")
        return x * 2
    return func


@pytest.fixture
def simple_wrapper(simple_function):
    """A simple wrapper for testing."""
    def wrapper(input_data):
        x = input_data.get("x", 0)
        return simple_function(x)
    return wrapper