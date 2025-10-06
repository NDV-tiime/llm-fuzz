from setuptools import find_packages, setup

setup(
    name="llm-fuzz",
    version="0.1.0",
    author="Nicolas Devatine & Louis Abraham",
    author_email="nicolas.devatine@tiime.fr",
    description="LLM-powered automated fuzzing tool for Python functions",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/NDV-tiime/llm-fuzz",
    packages=find_packages(exclude=["tests*", "examples*"]),
    classifiers=[],
    python_requires=">=3.8",
    install_requires=[
        "smolagents",
        "litellm",
        "jedi",
    ],
)
