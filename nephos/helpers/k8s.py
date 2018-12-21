from __future__ import print_function

import base64
import json

from blessings import Terminal
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from nephos.helpers.misc import execute, input_files, pretty_print

TERM = Terminal()


# Configs can be set in Configuration class directly or using helper utility
config.load_kube_config()
api = client.CoreV1Api()
api_ext = client.ExtensionsV1beta1Api()


# Class to execute K8S commands
class Executer:
    def __init__(self, pod, namespace, container='', verbose=False):
        extra = ''
        if container:
            extra += "--container {} ".format(container)
        self.pod = pod
        self.prefix_exec = "kubectl exec {pod} -n {namespace} {extra}-- ".format(
            pod=pod, namespace=namespace, extra=extra)
        self.prefix_logs = "kubectl logs {pod} -n {namespace} {extra}".format(
            pod=pod, namespace=namespace, extra=extra)
        self.verbose = verbose

    # TODO: api.connect_get_namespaced_pod_exec (to do exec using Python API programmatically)
    def execute(self, command):
        result = execute(
            self.prefix_exec + command,
            verbose=self.verbose
        )
        return result

    def logs(self, tail=-1):
        result = execute(
            self.prefix_logs + '--tail={}'.format(tail),
            verbose=self.verbose
        )
        return result


# Config
def context_get(verbose=False):
    contexts, active_context = config.list_kube_config_contexts()
    if verbose:
        pretty_print(json.dumps(active_context))
    return active_context


# Namespaces
def ns_create(namespace, verbose=False):
    try:
        ns_read(namespace, verbose=verbose)
    except ApiException:
        ns = client.V1Namespace()
        ns.metadata = client.V1ObjectMeta(name=namespace)
        api.create_namespace(ns)
        if verbose:
            print(TERM.green('Created namespace "{}"'.format(namespace)))
            pretty_print(json.dumps(ns.metadata, default=str))


def ns_read(namespace, verbose=False):
    ns = api.read_namespace(name=namespace)
    if verbose:
        pretty_print(json.dumps(ns.metadata, default=str))
    return ns


# Ingress
def ingress_read(name, namespace='default', verbose=False):
    ingress = api_ext.read_namespaced_ingress(name=name, namespace=namespace)
    hosts = [item.host for item in ingress.spec.rules]
    if verbose:
        pretty_print(json.dumps(hosts))
    return hosts


# Configmaps and secrets
# TODO: Refactor these so we have the same API as with secrets
def cm_create(namespace, name, cm_data):
    # TODO: We should check that CM exists before we create it
    # TODO: We should add verbose option
    cm = client.V1ConfigMap()
    cm.metadata = client.V1ObjectMeta(name=name)
    cm.data = cm_data
    api.create_namespaced_config_map(namespace=namespace, body=cm)


def cm_read(name, namespace, verbose=False):
    cm = api.read_namespaced_config_map(name=name, namespace=namespace)
    if verbose:
        pretty_print(json.dumps(cm.data))
    return cm.data


def secret_create(secret_data, name, namespace, verbose=False):
    # Encode the data in a copy of the input dictionary
    secret_data = secret_data.copy()
    for key, value in secret_data.items():
        if isinstance(value, str):
            value = value.encode('ascii')
        secret_data[key] = base64.b64encode(value).decode('utf-8')
    secret = client.V1Secret()
    secret.metadata = client.V1ObjectMeta(name=name)
    secret.type = "Opaque"
    secret.data = secret_data
    api.create_namespaced_secret(namespace=namespace, body=secret)
    if verbose:
        print('Created secret {} in namespace {}'.format(name, namespace))


def secret_read(name, namespace='default', verbose=False):
    secret = api.read_namespaced_secret(name=name, namespace=namespace)
    for key, value in secret.data.items():
        if value:
            secret.data[key] = base64.b64decode(value).decode('utf-8', 'ignore')
    if verbose:
        pretty_print(json.dumps(secret.data))
    return secret.data


def secret_from_file(secret, namespace, key=None, filename=None, verbose=False):
    try:
        secret_read(secret, namespace, verbose=verbose)
    except ApiException:
        # Get relevant variables
        if not filename:
            secret_data = input_files([key], secret, clean_key=True)
        else:
            with open(filename, 'rb') as f:
                data = f.read()
                secret_data = {key: data}
        secret_create(secret_data, secret, namespace, verbose=verbose)


def get_app_info(namespace, ingress, secret, secret_key='API_KEY', verbose=False):
    # Get ingress URL
    ingress_data = ingress_read(ingress, namespace=namespace, verbose=verbose)
    url = ingress_data[0]
    if not url:
        raise ValueError('Ingress is missing')
    # Get API_KEY from secret
    secret_data = secret_read(secret, namespace, verbose=verbose)
    apikey = secret_data[secret_key]
    # Return data
    data = {
        'api-key': apikey,
        'url': url
    }
    return data
