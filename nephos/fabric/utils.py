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
from os import path, rename
from kubernetes.client.rest import ApiException

from nephos.helpers.k8s import Executer, secret_create, secret_read, secret_from_files
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
    secret_from_files(
        secret=secret_name, namespace=namespace, keys_files_path={key: secret_files[0]}
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


def get_org_tls_ca_cert(opts, msp_namespace):
    """Get path to the directory containing tls CA certificate

        Args:
            opts (dict): Nephos options dict.
            msp_name (str): Name of Membership Service Provider.

        Returns:
            path: path to the directory containing tls CA certificate
    """

    if "tls_ca" in opts["ordering"]["tls"]:
        glob_target = f"{opts['core']['dir_crypto']}/tlscacerts/*.crt"
    else:
        glob_target = f"{opts['core']['dir_crypto']}/crypto-config/*Organizations/{msp_namespace}*/tlsca/*.pem"
    tls_path_list = glob(glob_target)
    if len(tls_path_list) == 1:
        return tls_path_list[0]
    else:
        raise ValueError(
            f"TLS path list length is {len(tls_path_list)} - {tls_path_list}"
        )


def get_tls_path(opts, id_type, namespace, release):
    """Get path to the directory containing TLS materials for a node
        Args:
            opts (dict): Nephos options dict.
            id_type (str): Type of ID we use.
            namespace (str): Name of namespace.
            release (str): Name of release/node.

        Returns:
            str: path to the directory containing materials of a node
    """

    if "tls_ca" in opts["ordering"]["tls"]:
        glob_target = f"{opts['core']['dir_crypto']}/{release}_TLS/tls"
    else:
        glob_target = f"{opts['core']['dir_crypto']}/crypto-config/{id_type}Organizations/{namespace}*/{id_type}s/{release}*/tls"
    tls_path_list = glob(glob_target)
    if len(tls_path_list) == 1:
        return tls_path_list[0]
    else:
        raise ValueError(
            f"MSP path list length is {len(tls_path_list)} - {tls_path_list}"
        )


def is_orderer_tls_true(opts):
    """Check if tls is enabled for orderer
        Args:
            opts (dict): Nephos options dict.

        Returns:
            bool: return true if tls is enabled for orderer and false otherwise
    """

    if "tls" in opts["ordering"]:
        return opts["ordering"]["tls"]["enable"] == True


def rename_file(directory, name):
    """Rename a single file within a folder
        Args:
            directory (string): Path to the folder
            name (string): name to which the file should be renamed
    """
    file_list = glob(path.join(directory, "*"))
    if len(file_list) == 1:
        file = file_list[0]
    else:
        raise ValueError(f"from_dir contains {len(file_list)} files - {file_list}")
    rename(file, path.join(directory, name))


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
        return opts["ordering"]["kafka"]
