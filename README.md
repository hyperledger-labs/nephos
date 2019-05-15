[![Build Status](https://travis-ci.com/aidtechnology/nephos.svg?branch=master)](https://travis-ci.org/hyperledger-labs/nephos)
[![Known Vulnerabilities](https://snyk.io/test/github/aidtechnology/nephos/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/hyperledger-labs/nephos?targetFile=requirements.txt)
[![<Sonarcloud quality gate>](https://sonarcloud.io/api/project_badges/measure?project=aidtechnology_nephos&metric=alert_status)](https://sonarcloud.io/dashboard?id=hyperledger-labs_nephos)
[![codecov.io](http://codecov.io/github/aidtechnology/nephos/coverage.svg?branch=master)](http://codecov.io/github/hyperledger-labs/nephos?branch=master)

# Nephos

Library to deploy [Hyperledger Fabric](https://hyperledger-fabric.readthedocs.io) projects to [Kubernetes](https://kubernetes.io/)

Source resides at https://github.com/hyperledger-labs/nephos, originally developed at **[AID:Tech](https://github.com/aidtechnology/nephos)**

Documentation resides at https://nephos.readthedocs.io

   * [Prerequisites](#prerequisites)
   * [Installation](#installation)
      * [Pip](#pip)
      * [Git repository](#git-repository)
         * [Virtual environment](#virtual-environment)
         * [Requirements](#requirements)
   * [Testing](#testing)
      * [Unit tests](#unit-tests)
   * [Usage](#usage)
   * [Examples](#examples)
      * [Development](#development)
      * [QA and Production](#qa-and-production)
      * [Minikube](#minikube)
   * [Further information](#further-information)
      * [Helm charts](#helm-charts)
      * [Educational material](#educational-material)
   * [Contributing to Nephos](#contributing-to-nephos)

## Prerequisites

This library requires an existing Kubernetes cluster.

For best results, use a real cluster (e.g. on a cloud like AWS, GCP, Azure, IBM Cloud, etc.). However, you may also use [Minikube](https://kubernetes.io/docs/setup/minikube/).

Either way, you will need to have the following tools installed:

- [python 3.7.0](https://www.python.org/downloads/release/python-370/) or above
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- [helm](https://docs.helm.sh/using_helm/#installing-helm)

## Installation

### Pip

You can install nephos from [PyPI](https://pypi.org/project/nephos/) by running:

    pip install nephos

### Git repository

You can also download the git repository with:

    git clone https://github.com/hyperledger-labs/nephos.git

And work locally by installing the following:

#### Virtual environment

This library currently only supports Python 3:

    python3 -m venv ./venv

    source ./venv/bin/activate

#### Requirements

All python-related requirments are held in the requirements.txt file

    pip install -r requirements.txt

You will also need to install an initialise `helm` for Kubernetes, as described [here](https://helm.sh/docs/using_helm/)

Furthermore, you will need the Hyperledger Fabric utility binaries that can be installed with this [script](https://raw.githubusercontent.com/hyperledger/fabric/master/scripts/bootstrap.sh) on Linux, or via Homebrew for the [Fabric tools](https://github.com/aidtechnology/homebrew-fabric) and [CA tools](https://github.com/aidtechnology/homebrew-fabric-ca) on Mac OS X.

## Testing

### Unit tests

Once you have all requirments installed, all the unit tests should pass and provide full coverage:

    PYTHONPATH=. pytest --ignore=./integration --cov=. --cov-report xml:coverage.xml --cov-report term-missing

The integration tests should also pass:

    PYTHONPATH=. pytest -x -s ./integration

## Usage

To use *nephos*, run the `deploy.py` executable CLI script.

For instance, you can see available commands/options by running:

    PYTHONPATH=. ./nephos/deploy.py --help

To install a full end-to-end fabric network, you can run:

    PYTHONPATH=. ./nephos/deploy.py -f ./PATH_TO_YOUR_SETTINGS/file.yaml fabric

You can also upgrade a network:

    PYTHONPATH=. ./nephos/deploy.py --upgrade -f ./PATH_TO_YOUR_SETTINGS/file.yaml fabric

## Examples

### Development

Example of development/QA/production(-ish) networks are provided in the examples folder.

To run the dev example from the git repository, use this command:

    ./nephos/deploy.py --verbose -f ./examples/dev/nephos_config.yaml fabric

> Note: The `nephos_config.yaml` is by default set to point to the `minikube` context (even for the `prod` example) to prevent accidental deployments to production clusters. If your K8S context name is different, please update this file.

### QA and Production

For the QA and production examples, you will need to replace the CA hostname to one pointing to your K8S cluster Ingress Controller  (e.g. NGINX or Traefik) IP address.

In a real cluster, you will wish to install an ingress controller and a certificate manager. We include in the repository two example Cluster Issuers (you will need to modify the email field in them) for the `cert-manager` deployment:

    helm install stable/nginx-ingress -n nginx-ingress --namespace ingress-controller

    helm install stable/cert-manager -n cert-manager --namespace cert-manager

    kubectl create -f ./examples/certManagerCI_staging.yaml

    kubectl create -f ./examples/certManagerCI_production.yaml

To use the Composer examples, you will need a Cloud system capable of a "ReadWriteMany" policy (e.g. "azurefile" on Azure).

### Minikube

Given that we may wish to test locally on Minikube, we will need to use a local ingress controller and ignore cert-manager in favour of self-cooked SSL certificates.

In `./examples` we include the `ca-nephos-local.*` self-signed certificates, created with OpenSSL as follows:

    openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 -subj "/C=IE/ST=Dublin/L=Dublin/O=AID:Tech/CN=ca.nephos.local" -keyout ca-nephos-local.key -out ca-nephos-local.crt

    openssl x509 -in ca-nephos-local.crt -out ca-nephos-local.pem -outform PEM

    kubectl create ns cas

    kubectl -n cas create secret tls ca--tls --cert=ca-nephos-local.crt --key=ca-nephos-local.key

We can save them to the `cas` namespace as follows

    cd ./examples

    kubectl create ns cas

    kubectl -n cas create secret tls ca--tls --cert=ca-nephos-local.crt --key=ca-nephos-local.key

We can then enable the ingress on minikube and update `/etc/hosts` with the IP of `minikube`:

    minikube addons enable ingress

    echo "$(minikube ip)  ca.nephos.local" | sudo tee -a /etc/hosts

## Further information

For more information on how to deploy Hyperledger Fabric to Kubernetes, please see the following resources:

### Helm charts

We have released a set of Helm Charts, currently living in two locations:

* The official Helm Chart [repository](https://github.com/helm/charts) and [KubeApps](https://hub.kubeapps.com/charts?q=hyperledger).
* The AID:Tech Helm Chart [repository](https://github.com/aidtechnology/at-charts).

### Educational material

A [workshop](https://hgf18.sched.com/event/b76c86de07c3bcaa094a8b149470e0e7) on the Hyperledger Global Forum, featuring [slides](https://schd.ws/hosted_files/hgf18/d2/2018_12_14_CH_Basel_Hyperledger_Global_Forum.pdf) and a [part 1](https://www.youtube.com/watch?v=ubrA3W1JMk0) and [part 2](https://www.youtube.com/watch?v=3tVk7yrGSSE) videos.

A(n older) [webinar](https://www.hyperledger.org/blog/2018/11/08/deploying-hyperledger-fabric-on-kubernetes) on deploying Hyperledger Fabric on Kubernetes.

We have also contributed the Composer chapter on the EdX course [Blockchain for Business](https://www.edx.org/course/blockchain-business-introduction-linuxfoundationx-lfs171x-0).

And we have also released a course on [Packt](https://www.packtpub.com/application-development/hyperledger-blockchain-applications-video), [Udemy](https://www.udemy.com/hyperledger-for-blockchain-applications/) and [O’Reilly](https://www.oreilly.com/library/view/hyperledger-for-blockchain/9781789131963/) called Hyperledger for Blockchain Applications.

## Contributing to Nephos

We welcome all PRs, especially those addressing issues mentioned in the GitHub Project.

To submit a PR, please make sure that:

1. Fork the repository to your own GitHub account.
2. All tests are passing, and there is 100% coverage on the unit tests.
3. All new/changed functions should be correctly documented with *docstrings* using the Google format.
4. Update the version number by editing the following files: `setup.py` (to update **VERSION**) and `docs/conf.py` (to update the **version** and **release**)

The documentation and pip package are auto-generated after approval and merging of the PR.
