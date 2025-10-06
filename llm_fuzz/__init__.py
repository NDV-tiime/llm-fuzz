"""
llm-fuzz: LLM-powered automated fuzzing tool for Python functions.
"""

from .fuzzer import FuzzConfig, FuzzReport, llm_fuzz

__version__ = "0.1.0"
__all__ = ["llm_fuzz", "FuzzConfig", "FuzzReport"]
