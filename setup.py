from setuptools import setup

# Available at setup time due to pyproject.toml
from pybind11.setup_helpers import Pybind11Extension, build_ext

__version__ = "0.0.1"

# Note:
#   Sort input source files if you glob sources to ensure bit-for-bit
#   reproducible builds (https://github.com/pybind/python_example/pull/53)

ext_modules = [
    Pybind11Extension(
        "oxen_bls",
        ["src/bls.cpp"],
        cxx_std=20,
        include_dirs=["/usr/include/oxen"],
        library_dirs=["/usr/lib/x86_64-linux-gnu/oxen"],
        runtime_library_dirs=["/usr/lib/x86_64-linux-gnu/oxen"],
        libraries=["bls_crypto"],
    ),
]

setup(
    name="oxen_bls",
    version=__version__,
    author="Jason Rhinelander",
    author_email="jason@session.foundatoin",
    url="https://github.com/oxen-io/oxen-core",
    description="Python wrapper for oxen-core BLS signature verification",
    long_description="",
    ext_modules=ext_modules,
    zip_safe=False,
)
