
from setuptools import setup

import rpsowmi


classifiers = [line.rstrip() for line in """\
License :: OSI Approved :: MIT License
Development Status :: 3 - Alpha
Programming Language :: Python :: 3.4
Programming Language :: Python :: 3.5
Programming Language :: Python :: 3.6
Operating System :: Microsoft :: Windows
Intended Audience :: Developers
""".splitlines()]

keywords = [line.rstrip() for line in """\
WMI
PowerShell
Remote
""".splitlines()]

with open("README.rst") as fp:
    long_description = fp.read()

setup(
    version=rpsowmi.__version__,
    name=rpsowmi.__name__,
    license=rpsowmi.__license__,
    url="https://github.com/sakurai-youhei/rpsowmi",
    description="Remote PowerShell over WMI (RPSoWMI)",
    long_description=long_description,
    classifiers=classifiers,
    keywords=keywords,
    author=rpsowmi.__author__,
    author_email=rpsowmi.__email__,
    py_modules=[rpsowmi.__name__],
    test_suite="test.suite",
)
