# Introduction

This pipeline can be imported into Azure Devops and used to automatically verify the syntax of the use-case files in the repository.

It is recommended to configure two policies in the repository on the main branch:

Setup a build validation policy:

![Build-validation-policy](screenshot_enable_build_validation.jpg)

Setup branch policy to disallow direct pushing to the main branch but require a pull request:

![Branch-policy](screenshot_example_branch_policies.jpg)
