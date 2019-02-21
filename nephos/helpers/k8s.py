from __future__ import print_function

import base64
import json
from shutil import which

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
    print(TERM.red('We do not have "kubectl" installed'))


# Class to execute K8S commands
# TODO: We might wish to set the container at the execution level?
class Executer:
    def __init__(self, pod, namespace, container="", verbose=False):
        """Executer creates a K8S pod object capable of:
        1) Execute commands,
        2) Return logs.

        Args:
            pod (str): Pod to bind to.
            namespace (str): Name of namespace.
            container (str): Container to bind to.
            verbose (bool): Verbosity. False by default.
        """
        extra = ""
        if container:
            extra += "--container {} ".format(container)
        self.pod = pod
        self.prefix_exec = "kubectl exec {pod} -n {namespace} {extra}-- ".format(
            pod=pod, namespace=namespace, extra=extra
        )
        self.prefix_logs = "kubectl logs {pod} -n {namespace} {extra}".format(
            pod=pod, namespace=namespace, extra=extra
        )
        self.verbose = verbose

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
        result, error = execute(self.prefix_exec + command, verbose=self.verbose)
        return result, error

    def logs(self, tail=-1, since_time=None):
        """Get logs from pod.

        Args:
            tail (int): How many lines of logs to obtain?

        Returns:
            str: Logs contained in pod.
        """
        command = "--tail={}".format(tail)
        if since_time:
            command += " --since-time='{}'".format(since_time)
        result, _ = execute(self.prefix_logs + command, verbose=self.verbose)
        return result


# Config
def context_get(verbose=False):
    """Obtain active K8S context.

    Args:
        verbose (bool): Verbosity. False by default.

    Returns:
        object: Active context.
    """
    _, active_context = config.list_kube_config_contexts()
    if verbose:
        pretty_print(json.dumps(active_context))
    return active_context


# Namespaces
def ns_create(namespace, verbose=False):
    """Create K8S namespace.

    Args:
        namespace (str): Name of namespace.
        verbose (bool): Verbosity. False by default.
    """
    try:
        ns_read(namespace, verbose=verbose)
    except ApiException:
        ns = client.V1Namespace()
        ns.metadata = client.V1ObjectMeta(name=namespace)
        api.create_namespace(ns)
        if verbose:
            print(TERM.green('Created namespace "{}"'.format(namespace)))
            pretty_print(json.dumps(ns.metadata, default=str))


# TODO: Can we be more precise with the return type annotation?
def ns_read(namespace, verbose=False):
    """Read Name of namespace.

    Args:
        namespace (str): Name of namespace.
        verbose (bool): Verbosity. False by default.

    Returns:
        object: Namespace object.
    """
    ns = api.read_namespace(name=namespace)
    if verbose:
        pretty_print(json.dumps(ns.metadata, default=str))
    return ns


# Ingress
# TODO: Convert list to tuple
def ingress_read(name, namespace="default", verbose=False):
    """Get host names contained in K8S Ingress.

    Args:
        name (str): Name of Ingress.
        namespace (str): Name of namespace.
        verbose (bool): Verbosity. False by default.

    Returns:
        list: List of host names.
    """
    ingress = api_ext.read_namespaced_ingress(name=name, namespace=namespace)
    hosts = [item.host for item in ingress.spec.rules if item.host]
    if verbose:
        pretty_print(json.dumps(hosts))
    return hosts


# Configmaps and secrets
# TODO: Refactor these so we have the same API as with secrets
def cm_create(namespace, name, cm_data):
    """Create a K8S ConfigMap

    Args:
        namespace (str): Name of namespace.
        name (str): Name of ConfigMap.
        cm_data (dict): Data to store in ConfigMap as key/value hash.
    """
    # TODO: We should check that CM exists before we create it
    # TODO: We should add verbose option
    cm = client.V1ConfigMap()
    cm.metadata = client.V1ObjectMeta(name=name)
    cm.data = cm_data
    api.create_namespaced_config_map(namespace=namespace, body=cm)


def cm_read(name, namespace, verbose=False):
    """Read a K8S ConfigMap.

    Args:
        name (str): Name of the ConfigMap.
        namespace (str): Name of namespace.
        verbose (bool): Verbosity. False by default.

    Returns:
        dict: Keys and values stored in the ConfigMap.
    """
    cm = api.read_namespaced_config_map(name=name, namespace=namespace)
    if verbose:
        pretty_print(json.dumps(cm.data))
    return cm.data


def secret_create(secret_data, name, namespace, verbose=False):
    """Create a K8S Secret.

    Args:
        secret_data (dict): Data to store in t as key/value hash.
        name (str): Name of the Secret.
        namespace (str): Name of namespace.
        verbose (bool): Verbosity. False by default.
    """
    # Encode the data in a copy of the input dictionary
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
    if verbose:
        print("Created secret {} in namespace {}".format(name, namespace))


def secret_read(name, namespace="default", verbose=False):
    """Read a K8S Secret.

    Args:
        name (str): Name of the Secret.
        namespace (str): Name of namespace.
        verbose (bool): Verbosity. False by default.

    Returns:
        dict: Keys and values stored in the Secret.
    """
    secret = api.read_namespaced_secret(name=name, namespace=namespace)
    for key, value in secret.data.items():
        if value:
            secret.data[key] = base64.b64decode(value).decode("utf-8", "ignore")
    if verbose:
        pretty_print(json.dumps(secret.data))
    return secret.data


def secret_from_file(secret, namespace, key=None, filename=None, verbose=False):
    """Convert a file into a K8S Secret.

    Args:
        secret (str): Name of Secret where to save the file.
        namespace (str): Name of namespace.
        key (str): Key to which to assign the file in the K8S t. If not specified, the filename is used.
        filename (str): If not provided, we ask the user for input.
        verbose (bool): Verbosity. False by default.
    """
    try:
        secret_read(secret, namespace, verbose=verbose)
    except ApiException:
        # Get relevant variables
        if not filename:
            secret_data = input_files((key,), secret, clean_key=True)
        else:
            with open(filename, "rb") as f:
                data = f.read()
                secret_data = {key: data}
        secret_create(secret_data, secret, namespace, verbose=verbose)


def get_app_info(namespace, ingress, secret, secret_key="API_KEY", verbose=False):
    """Get application information.

    Args:
        namespace (str): Name of namespace.
        ingress (str): Ingress name.
        secret (str): Secret where access details (e.g. API key) are located.
        secret_key (str): Key in t containing access details. By default "API KEY"
        verbose (bool): Verbosity. False by default.

    Returns:

    """
    # Get ingress URL
    ingress_data = ingress_read(ingress, namespace=namespace, verbose=verbose)
    url = ingress_data[0]
    # Get API_KEY from secret
    secret_data = secret_read(secret, namespace, verbose=verbose)
    apikey = secret_data[secret_key]
    # Return data
    data = {"api-key": apikey, "url": url}
    return data
