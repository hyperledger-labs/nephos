# nephos

Library to deploy Hyperledger Fabric projects to a Kubernetes cloud

   * [Prerequisites](#prerequisites)
   * [Installation](#installation)
      * [Virtual environment](#virtual-environment)
      * [Requirements](#requirements)
   * [Testing](#testing)
      * [Unit tests](#unit-tests)
   * [Usage](#usage)

## Prerequisites

This library requires an existing Kubernetes cluster.

For best results, use a real cluster (e.g. on a cloud like AWS, GCP, Azure, IBM Cloud, etc.). However, you may also use [Minikube](https://kubernetes.io/docs/setup/minikube/).

Either way, you will need to have the following tools installed:

- [python 3.7.0](https://www.python.org/downloads/release/python-370/) or above
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- [helm](https://docs.helm.sh/using_helm/#installing-helm)

## Installation

### Virtual environment

This library currently only supports Python 3:

    python3 -m venv ./venv

    source ./venv/bin/activate

### Requirements

All requirments are held in the requirements.txt file

    pip install -r requirements.txt

## Testing

### Unit tests

Once you have all requirments installed, all the unit tests should pass:

    PYTHONPATH=. pytest --cov=. --cov-report term-missing

## Usage


