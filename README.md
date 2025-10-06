# LLM Fuzz

AI-powered security testing framework for Python functions. Uses LLMs to analyze code, discover vulnerabilities, and generate targeted test cases.

## Installation

### From PyPI

```bash
pip install llm-fuzz
```

### From Source

```bash
git clone https://github.com/yourusername/llm-fuzz.git
cd llm-fuzz
pip install -e .
```

## Prerequisites

LLM Fuzz uses [smolagents](https://github.com/huggingface/smolagents) which supports multiple LLM providers through LiteLLM. You need to set up an API key for your chosen provider.

### Supported LLM Providers

- **OpenAI** (GPT-4, GPT-3.5, etc.)
- **Anthropic** (Claude)
- **Google** (Gemini)
- **Many others** via [LiteLLM](https://docs.litellm.ai/docs/providers)

### Setting Up API Keys

Before using llm-fuzz, export your API key:

```bash
# For OpenAI
export OPENAI_API_KEY="your-key-here"

# For Anthropic (Claude)
export ANTHROPIC_API_KEY="your-key-here"

# For Google (Gemini)
export GEMINI_API_KEY="your-key-here"
```

## Quick Start

```python
from llm_fuzz import llm_fuzz, FuzzConfig

# Your function to test
def divide(x, y):
    return x / y

# Wrapper for testing
def divide_wrapper(input_data):
    x = input_data.get("x", 1)
    y = input_data.get("y", 1)
    return divide(x, y)

# Configure and run fuzzer
config = FuzzConfig(
    model="gemini/gemini-2.5-flash",  # or "gpt-4", "claude-3-opus", etc.
    max_vulnerabilities=3,
    tests_per_vulnerability=2,
)

report = llm_fuzz(
    target_function=divide,
    test_function=divide_wrapper,
    config=config,
    fuzz_params=["x", "y"]
)

print(f"Tests: {report.passed_count}/{report.total_count} passed")
report.save_to_file("fuzz_report.json")
```

## Configuration

```python
FuzzConfig(
    model="gemini/gemini-2.5-flash",   # LLM model to use
    max_vulnerabilities=5,             # Number of vulnerabilities to discover
    tests_per_vulnerability=3,         # Test cases per vulnerability
    max_discovery_steps=15,            # Max steps for discovery
    temperature=0.1,                   # LLM temperature
    verbose=False                      # Enable verbose logging
)
```

## Examples

See the [`examples/`](examples/) directory:

- **[simple_division.py](examples/simple_division.py)** - Basic fuzzing example

Run the example:

```bash
export GEMINI_API_KEY="your-key"
python examples/simple_division.py
```

## Testing

Run the test suite:

```bash
pytest
```