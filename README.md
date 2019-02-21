[![Build Status](https://travis-ci.com/aidtechnology/nephos.svg?branch=master)](https://travis-ci.com/aidtechnology/nephos)
[![Known Vulnerabilities](https://snyk.io/test/github/aidtechnology/nephos/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/aidtechnology/nephos?targetFile=requirements.txt)
[![<Sonarcloud quality gate>](https://sonarcloud.io/api/project_badges/measure?project=aidtechnology_nephos&metric=alert_status)](https://sonarcloud.io/dashboard?id=aidtechnology_nephos)

# nephos

Library to deploy Hyperledger Fabric projects to Kubernetes.

Source resides here: https://github.com/aidtechnology/nephos
Documentation resides here: https://nephos.readthedocs.io

   * [Prerequisites](#prerequisites)
   * [Installation](#installation)
      * [Pip](#pip)
      * [Git repository](#git-repository)
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

### Pip

You can install nephos from PyPI by running:

    pip install nephos

### Git repository

You can also download the git repository with:

    git clone https://github.com/aidtechnology/nephos.git

And work locally by installing the following:

#### Virtual environment

This library currently only supports Python 3:

    python3 -m venv ./venv

    source ./venv/bin/activate

#### Requirements

All requirments are held in the requirements.txt file

    pip install -r requirements.txt

## Testing

### Unit tests

Once you have all requirments installed, all the unit tests should pass:

    PYTHONPATH=. pytest --cov=. --cov-report term-missing

## Usage

To use *nephos*, run the `deploy.py` executable CLI script.

For instance, you can see available commands/options by running:

    ./nephos/deploy.py --help

To install a full end-to-end fabric network, you can run:

    ./nephos/deploy.py -f ./PATH_TO_YOUR_SETTINGS/file.yaml fabric

You can also upgrade a network:

    ./nephos/deploy.py --upgrade -f ./PATH_TO_YOUR_SETTINGS/file.yaml fabric


## Examples

Example of development/QA/production(-ish) networks are provided in the examples folder.

To run the dev example from the git repository, use this command:

    ./nephos/deploy.py --verbose -f ./examples/dev/nephos_settings.yaml fabric

For the QA and production examples, you will need to replace the CA hostname to one pointing to your K8S cluster Ingress Controller  (e.g. NGINX or Traefik) IP address.

For instance, you may wish to install an ingress controller and a certificate manager. We include in the repository two example Cluster Issuers (you will need to modify the email field in them) for the `cert-manager` deployment:

    helm install stable/nginx-ingress -n nginx-ingress --namespace ingress-controller

    helm install stable/cert-manager -n cert-manager --namespace cert-manager

    kubectl create -f ./examples/certManagerCI_staging.yaml

    kubectl create -f ./examples/certManagerCI_production.yaml

To use the Composer examples, you will need a Cloud system capable of a "ReadWriteMany" policy (e.g. "azurefile" on Azure).
