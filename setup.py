#!/usr/bin/env python3

# from glob import glob
from setuptools import setup, find_packages
# from pybind11.setup_helpers import Pybind11Extension/

VERSION = 1.0
DESCRIPTION = 'Access windows anitmalware interface using python'
LONG_DESCRIPTION = ''

# ext_modules = [
#     Pybind11Extension(
#         "amsiscanner",
#         sorted(glob("src/pyamsi/scanner.cpp"))
#     ),
# ]

setup(
    name='py-amsi',
    version=VERSION,
    license='MIT',
    author="Olorunfemi-Ojo Tomiwa",
    author_email='ot.server1@outlook.com',
    description=DESCRIPTION,
    long_description_content_type='text/markdown',
    long_description=LONG_DESCRIPTION,
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/Tomiwa-Ot/py-amsi',
    keywords=['amsi', 'python-amsi', 'pyamsi'],
)
