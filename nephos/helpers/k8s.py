from __future__ import print_function

import base64
import json
from shutil import which
from time import sleep
import logging

from blessings import Terminal
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from nephos.helpers.misc import execute, input_files, pretty_print

TERM = Terminal()


# Configs can be set in Configuration class directly or using helper utility
if which("kubectl"):
    config.load_kube_config()
    api = client.CoreV1Api()
    api_ext = client.ExtensionsV1beta1Api()
else:  # pragma: no cover
    logging.critical(TERM.red('We do not have "kubectl" installed'))


# Class to execute K8S commands
# TODO: We might wish to set the container at the execution level?
class Executer:
    def __init__(self, pod, namespace, container=""):
        """Executer creates a K8S pod object capable of:
        1) Execute commands,
        2) Return logs.

        Args:
            pod (str): Pod to bind to.
            namespace (str): Name of namespace.
            container (str): Container to bind to.
        """
        extra = ""
        if container:
            extra += f"--container {container} "
        self.pod = pod
        self.prefix_exec = f"kubectl exec {pod} -n {namespace} {extra}-- "

        self.prefix_logs = f"kubectl logs {pod} -n {namespace} {extra}"

    # TODO: api.connect_get_namespaced_pod_exec (to do exec using Python API programmatically)
    def execute(self, command):
        """Execute a command in pod.

        Args:
            command (str): Command to execute.

        Returns:
            tuple: 2-tuple of execution info:
            1) result of the command, if successful, None if not;
            2) and error, if command failed, None if not.

        """
        result, error = execute(self.prefix_exec + command)
        return result, error

    def logs(self, tail=-1, since_time=None):
        """Get logs from pod.

        Args:
            tail (int): How many lines of logs to obtain?

        Returns:
            str: Logs contained in pod.
        """
        command = f"--tail={tail}"
        if since_time:
            command += f" --since-time='{since_time}'"
        result, _ = execute(self.prefix_logs + command)
        return result


# Config
def context_get():
    """Obtain active K8S context.

    Returns:
        object: Active context.
    """
    _, active_context = config.list_kube_config_contexts()
    logging.debug(pretty_print(json.dumps(active_context)))
    return active_context


# Namespaces
def ns_create(namespace):
    """Create K8S namespace.

    Args:
        namespace (str): Name of namespace.
    """
    try:
        ns_read(namespace)
    except ApiException:
        ns = client.V1Namespace()
        ns.metadata = client.V1ObjectMeta(name=namespace)
        api.create_namespace(ns)
        logging.info(f'Created namespace "{namespace}"')
        logging.debug(pretty_print(json.dumps(ns.metadata, default=str)))


# TODO: Can we be more precise with the return type annotation?
def ns_read(namespace):
    """Read Name of namespace.

    Args:
        namespace (str): Name of namespace.

    Returns:
        object: Namespace object.
    """
    ns = api.read_namespace(name=namespace)
    logging.debug(pretty_print(json.dumps(ns.metadata, default=str)))
    return ns


# Ingress
# TODO: Convert list to tuple
def ingress_read(name, namespace="default"):
    """Get host names contained in K8S Ingress.

    Args:
        name (str): Name of Ingress.
        namespace (str): Name of namespace.

    Returns:
        list: List of host names.
    """
    ingress = api_ext.read_namespaced_ingress(name=name, namespace=namespace)
    hosts = [item.host for item in ingress.spec.rules if item.host]
    logging.debug(pretty_print(json.dumps(hosts)))
    return hosts


# Pods
# TODO: We should not need to specify pod number.
def pod_check(namespace, identifier, sleep_interval=10, pod_num=None):
    """Check if a set of pods exist and are functional.

    Args:
        namespace (str): Namespace where Helm deployment is located.
        identifier (str): Name of pod, or a label descriptor.
        sleep_interval (int): Number of seconds to sleep between attempts.
        pod_num (int): Number of pods expected to exist in the release. None by default.
    """
    logging.info("Ensuring that all pods are running ")
    running = False
    while not running:
        states, _ = execute(
            f'kubectl get pods -n {namespace} {identifier} -o jsonpath="{{.items[*].status.phase}}"'
        )
        states_list = states.split()
        # Let us also check the number of pods we have
        # We keep checking the state of the pods until they are running
        states = set(states_list)
        if (
            len(states) == 1
            and "Running" in states
            and (pod_num is None or len(states_list) == pod_num)
        ):
            logging.info(TERM.green("All pods are running"))
            running = True
        else:
            print(TERM.red("."), end="", flush=True)
            sleep(sleep_interval)


# Configmaps and secrets
# TODO: Refactor these so we have the same API as with secrets
def cm_create(cm_data, name, namespace="default"):
    """Create a K8S ConfigMap

    Args:
        cm_data (dict): Data to store in ConfigMap as key/value hash.
        name (str): Name of ConfigMap.
        namespace (str): Name of namespace.
    """
    # TODO: We should check that CM exists before we create it
    cm = client.V1ConfigMap()
    cm.metadata = client.V1ObjectMeta(name=name)
    cm.data = cm_data
    api.create_namespaced_config_map(namespace=namespace, body=cm)
    logging.info(f"Created ConfigMap {name} in namespace {namespace}")


def cm_read(name, namespace="default"):
    """Read a K8S ConfigMap.

    Args:
        name (str): Name of the ConfigMap.
        namespace (str): Name of namespace.

    Returns:
        dict: Keys and values stored in the ConfigMap.
    """
    cm = api.read_namespaced_config_map(name=name, namespace=namespace)
    logging.debug(pretty_print(json.dumps(cm.data)))
    return cm.data


def secret_create(secret_data, name, namespace="default"):
    """Create a K8S Secret.

    Args:
        secret_data (dict): Data to store in t as key/value hash.
        name (str): Name of the Secret.
        namespace (str): Name of namespace.
    """
    # Encode the data in a copy of the input dictionary
    # TODO: We should check that Secret exists before we create it
    secret_data = secret_data.copy()
    for key, value in secret_data.items():
        if isinstance(value, str):
            value = value.encode("ascii")
        secret_data[key] = base64.b64encode(value).decode("utf-8")
    secret = client.V1Secret()
    secret.metadata = client.V1ObjectMeta(name=name)
    secret.type = "Opaque"
    secret.data = secret_data
    api.create_namespaced_secret(namespace=namespace, body=secret)
    logging.info(f"Created Secret {name} in namespace {namespace}")


def secret_read(name, namespace="default"):
    """Read a K8S Secret.

    Args:
        name (str): Name of the Secret.
        namespace (str): Name of namespace.

    Returns:
        dict: Keys and values stored in the Secret.
    """
    secret = api.read_namespaced_secret(name=name, namespace=namespace)
    for key, value in secret.data.items():
        if value:
            secret.data[key] = base64.b64decode(value).decode("utf-8", "ignore")
    logging.debug(pretty_print(json.dumps(secret.data)))
    return secret.data


def secret_from_file(secret, namespace, key=None, filename=None):
    """Convert a file into a K8S Secret.

    Args:
        secret (str): Name of Secret where to save the file.
        namespace (str): Name of namespace.
        key (str): Key to which to assign the file in the K8S t. If not specified, the filename is used.
        filename (str): If not provided, we ask the user for input.
    """
    try:
        secret_read(secret, namespace)
    except ApiException:
        # Get relevant variables
        if not filename:
            secret_data = input_files((key,), clean_key=True)
        else:
            with open(filename, "rb") as f:
                data = f.read()
                secret_data = {key: data}
        secret_create(secret_data, secret, namespace)


def get_app_info(namespace, ingress, secret, secret_key="API_KEY"):
    """Get application information.

    Args:
        namespace (str): Name of namespace.
        ingress (str): Ingress name.
        secret (str): Secret where access details (e.g. API key) are located.
        secret_key (str): Key in t containing access details. By default "API KEY"

    Returns:

    """
    # Get ingress URL
    ingress_data = ingress_read(ingress, namespace=namespace)
    url = ingress_data[0]
    # Get API_KEY from secret
    secret_data = secret_read(secret, namespace)
    apikey = secret_data[secret_key]
    # Return data
    data = {"api-key": apikey, "url": url}
    return data
