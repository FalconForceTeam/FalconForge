# Introduction

Welcome to the FalconForge repository. This repository is used by FalconForce to release parts of the
internal tools used for maintaining, validating and automatically deploying a repository consisting of use-cases
for the Sentinel and Microsoft 365 Defender products.

The repository is structured as follows:
* `src` - Contains the source code for the tools.
* `docs` - Contains the documentation for the tools.
* `docs/schemas` - Contains the schemas used by the various yaml formats in use in this repository.
* `usecases` - Contains example use-cases converted to the usecase.yaml format used by the tools.
* `pipelines` - Contains example pipelines for Azure DevOps that can be used to automate use-case validation.

## Installing the tools

The tools are written in Python it is recommended to use a virtual environment to install the tools.

```
python3 -m venv venv
source venv/bin/activate
pip install -r src/requirements.txt
```

## Using the tools

Currently only a single tool has been released `verify.py`. This tool is used to verify the
structure of a repository consisting of use-cases for Sentinel and Microsoft 365 Defender.

The tool can be run as follows:

```
python3 src/verify.py
```

Two flags can be used on the command-line:
* `--analyzer-url` - The URL to the analyzer service. This should point to an instance of the [KQL Query Analyzer REST service](https://github.com/FalconForceTeam/KQLAnalyzer). If this flag is not specified no validation of the KQL queries will be performed.
* `--strict` - If this flag is specified the tool will exit with a non-zero exit code if any errors or warnings are found. This is useful for CI/CD pipelines.



