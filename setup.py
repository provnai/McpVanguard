from setuptools import setup, find_packages

setup(
    name="mcp-vanguard",
    version="0.1.0",
    description="Security proxy and verification layer for the Model Context Protocol (MCP)",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Provnai Development Team",
    author_email="research@provnai.com",
    url="https://github.com/provnai/McpVanguard",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "mcp>=1.0.0",
        "fastmcp>=0.9.0",
        "uvloop>=0.19.0",
        "pyyaml>=6.0",
        "httpx>=0.27.0",
        "typer>=0.12.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "semantic": ["llama-cpp-python>=0.2.0"],
        "cloud": ["supabase>=2.0.0"],
        "dev": ["pytest>=8.0.0", "pytest-asyncio>=0.23.0"],
    },
    entry_points={
        "console_scripts": ["vanguard=core.cli:app"],
    },
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="mcp ai security proxy llm agent antivirus",
)
