"""
Some python wrappers around ptrace.
"""

from composer_extensions import ptrace_wrapper
from .process_interface import ProcessMemory

__all__ = ["ptrace_wrapper", "ProcessMemory"]
