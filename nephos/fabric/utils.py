#   Copyright [2018] [Alejandro Vicente Grabovetsky via AID:Tech]
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at#
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from glob import glob
from os import path

from kubernetes.client.rest import ApiException

from nephos.helpers.k8s import Executer, secret_create, secret_from_file, secret_read
from nephos.helpers.misc import execute, rand_string


def credentials_secret(secret_name, namespace, username, password=None):
    """Create a CA credentials secret.

    Args:
        secret_name (str): Name of secret.
        namespace (str): Namespace for secret to be located.
        username (str): Username for credentials secret.
        password (str): Password for credentials secret.

    Returns:
        dict: Secret data including "CA_USERNAME" and "CA_PASSWORD"
    """
    try:
        secret_data = secret_read(secret_name, namespace)
        # Check that the ID stored is the same as Orderer name
        # TODO: Remove asserts here, instead raise error
        assert username == secret_data["CA_USERNAME"]
        if password:
            assert password == secret_data["CA_PASSWORD"]
    except ApiException:
        # Get relevant variables
        if not password:
            password = rand_string(24)
        secret_data = {"CA_USERNAME": username, "CA_PASSWORD": password}
        secret_create(secret_data, secret_name, namespace)
    return secret_data


def crypto_secret(secret_name, namespace, file_path, key):
    """Create a crypto-material secret.

    Args:
        secret_name (str): Name of secret.
        namespace (str): Namespace for secret to be located.
        file_path (str): Path to file we want to store as a secret.
        key (str): Key (file) name of secret we want to store as a secret.
    """
    secret_files = glob(path.join(file_path, "*"))
    if len(secret_files) != 1:
        raise Exception("We should only find one file in this directory")
    secret_from_file(
        secret=secret_name,
        namespace=namespace,
        key=key,
        filename=secret_files[0],
    )


# TODO: Move this to K8S helpers
def get_pod(namespace, identifier, item=0):
    """Get a pod object from K8S.

    Args:
        namespace (str): Namespace where pod is located.
        identifier (str): Name of pod, or a label descriptor.

    Returns:
        Executer: A pod object able to execute commands and return logs.
    """
    node_pod, _ = execute(
        (
            f"kubectl get pods -n {namespace} {identifier} "
            + f'-o jsonpath="{{.items[{item}].metadata.name}}"'
        )
    )
    if not node_pod:
        raise ValueError('"node_pod" should contain a value')
    pod_ex = Executer(node_pod, namespace=namespace)
    return pod_ex


# TODO: Move this to Helm helpers
def get_helm_pod(namespace, release, app, item=0):
    """Get a pod object from K8S.

    Args:
        namespace (str): Namespace where pod is located.
        release (str): Release name of pod.
        app (str): App type of pod.

    Returns:
        Executer: A pod object able to execute commands and return logs.
    """
    identifier = f'-l "app={app},release={release}"'
    return get_pod(namespace, identifier, item=item)


def get_orderers(opts, msp):
    if "orderers" in opts["msps"][msp] and "nodes" in opts["msps"][msp]["orderers"]:
        return opts["msps"][msp]["orderers"]["nodes"].keys()
    return []


# No real purpose in asking the msp for now, but will needed to support multi-org
def get_peers(opts, msp):
    if "peers" in opts["msps"][msp]:
        return opts["msps"][msp]["peers"]["nodes"].keys()
    return []


def is_orderer_msp(opts, msp):
    if "orderers" in opts["msps"][msp] and "nodes" in opts["msps"][msp]["orderers"]:
        return True
    return False


def get_an_orderer_msp(opts):
    for msp in opts["msps"]:
        if is_orderer_msp(opts=opts, msp=msp):
            return msp


def get_msps(opts):
    return opts["msps"].keys()


def get_channels(opts):
    return opts["channels"].keys()


def get_secret_genesis(opts):
    return opts["ordering"]["secret_genesis"]


def get_kafka_configs(opts):
    if "kafka" in opts["ordering"]:
        return opts['ordering']['kafka']
