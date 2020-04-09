"""
Contains the the abstraction for working with ELF files.
"""

from composer_extensions import elf_handler
from .elflib import ELFFile

__all__ = ["ELFFile", "elf_handler"]
