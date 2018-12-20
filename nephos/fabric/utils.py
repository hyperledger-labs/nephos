from glob import glob
from os import path
import random
from string import ascii_letters, digits

from kubernetes.client.rest import ApiException

from nephos.helpers.k8s import Executer, secret_create, secret_from_file, secret_read
from nephos.helpers.misc import execute


def rand_string(length):
    return ''.join(random.choice(ascii_letters + digits) for _ in range(length))


def credentials_secret(secret_name, namespace, username, password=None, verbose=False):
    try:
        secret_data = secret_read(secret_name, namespace, verbose=verbose)
        # Check that the ID stored is the same as Orderer name
        assert username == secret_data['CA_USERNAME']
        if password:
            assert password == secret_data['CA_PASSWORD']
    except ApiException:
        # Get relevant variables
        if not password:
            password = rand_string(24)
        secret_data = {
            'CA_USERNAME': username,
            'CA_PASSWORD': password
        }
        secret_create(secret_data, secret_name, namespace)
    return secret_data


def crypto_secret(secret_name, namespace, file_path, key, verbose=False):
    secret_files = glob(path.join(file_path, '*'))
    if len(secret_files) != 1:
        raise Exception('We should only find one file in this directory')
    secret_from_file(secret=secret_name, namespace=namespace,
                     key=key, filename=secret_files[0], verbose=verbose)


def get_pod(namespace, release, app, verbose=False):
    node_pod = execute(
        ('kubectl get pods -n {ns} -l "app={app},release={release}" ' +
         '-o jsonpath="{{.items[0].metadata.name}}"').format(
            ns=namespace,
            app=app,
            release=release
        ), verbose=verbose)
    if not node_pod:
        raise ValueError('"node_pod" should contain a value')
    pod_ex = Executer(node_pod, namespace=namespace, verbose=verbose)
    return pod_ex
