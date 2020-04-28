"""
Contains the the abstraction for working with ELF files.
"""

from .elflib import ELFFile
from composer_extensions import elf_handler

__all__ = ["ELFFile", "elf_handler"]
