from distutils.core import setup, Extension

module1 = Extension('elf_handler',
                    extra_compile_args = ['-Werror', '-Wpedantic'],
                    sources = ['elf_handler.c'])

setup (name = 'elf_handler',
       version = '1.0',
       description = 'This is a demo package',
       ext_modules = [module1])
