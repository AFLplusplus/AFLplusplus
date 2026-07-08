"""Setup script for AFL++ MCP Server."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aflpp-mcp-server",
    version="0.1.0",
    author="AFL++ MCP Server Contributors",
    description="Model Context Protocol server for AFL++ fuzzing analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AFLplusplus/AFLplusplus",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "mcp>=1.0.0",
    ],
    extras_require={
        "sse": [
            "starlette>=0.27.0",
            "uvicorn>=0.24.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "aflpp-mcp-server=mcp.server:main",
        ],
    },
)
