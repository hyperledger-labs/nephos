from __future__ import print_function

from collections import namedtuple
from os import path
from time import sleep
import logging

from blessings import Terminal

from nephos.helpers.k8s import pod_check, secret_read
from nephos.helpers.misc import execute

TERM = Terminal()

HelmPreserve = namedtuple(
    "HelmPreserve", ("secret_namespace", "secret_name", "data_item", "values_path")
)
# noinspection PyArgumentList
HelmSet = namedtuple("HelmSet", ("key", "value", "set_string"), defaults=(False,))

CURRENT_DIR = path.abspath(path.split(__file__)[0])


# TODO: We should be able to get the namespace from the Helm release...
def helm_check(app, release, namespace, pod_num=None):
    """Check if a Helm release exists and is functional.

    Args:
        app (str): Helm application name.
        release (str): Release name on K8S.
        namespace (str): Namespace where Helm deployment is located.
        pod_num (int): Number of pods expected to exist in the release.
    """
    identifier = f'-l "app={app},release={release}"'
    pod_check(namespace, identifier, pod_num=pod_num)


def helm_init():
    """Initialise Helm on cluster, using RBAC."""
    res, _ = execute("helm list")
    if res is not None:
        logging.info(TERM.green("Helm is already installed!"))
    else:
        execute(f"kubectl create -f {CURRENT_DIR}/../extras/helm-rbac.yaml")
        execute("helm init --service-account tiller")
        # Fix issue with automountServiceToken
        res, _ = execute(
            "kubectl -n kube-system get deployment tiller-deploy "
            + '-o jsonpath="{.spec.template.spec.automountServiceAccountToken}"'
        )
        if res == "false":
            execute(
                "kubectl -n kube-system patch deployment tiller-deploy "
                + '-p \'{"spec": {"template": {"spec": {"automountServiceAccountToken": true}}}}\''
            )
        # We keep checking the state of helm until everything is running
        running = False
        while not running:
            res, _ = execute("helm list")
            if res is not None:
                running = True
            else:
                print(TERM.red("."), end="", flush=True)
                sleep(15)


def helm_env_vars(env_vars):
    """Convert environmental variables to a "--set" string for Helm deployments.

    Args:
        env_vars (Iterable): Environmental variables we wish to store in Helm.

    Returns:
        str: String containing variables to be set with Helm release.
    """
    env_vars = list(env_vars)
    for i, item in enumerate(env_vars):
        if isinstance(item, tuple):
            item = HelmSet(*item)
        elif not isinstance(item, HelmSet):
            raise TypeError("Items in env_vars array must be HelmSet named tuples")
        env_vars[i] = item
    # Environmental variables
    # TODO: This may well be its own subfunction
    env_vars_string = "".join(
        [
            " --set{} {}={}".format(
                "-string" if item.set_string else "", item.key, item.value
            )
            for item in env_vars
        ]
    )
    return env_vars_string


def helm_preserve(preserve):
    """Convert secret data to a "--set" string for Helm deployments.

    Args:
        preserve (Iterable): Set of secrets we wish to get data from to assign to the Helm Chart.


    Returns:
        str: String containing variables to be set with Helm release.
    """

    env_vars = []
    for item in preserve:
        if isinstance(item, tuple):
            item = HelmPreserve(*item)
        elif not isinstance(item, HelmPreserve):
            raise TypeError("Items in preserve array must be HelmPerserve named tuples")
        secret_data = secret_read(
            item.secret_name, item.secret_namespace
        )
        env_vars.append(HelmSet(item.values_path, secret_data[item.data_item]))
    # Environmental variables
    # TODO: This may well be its own subfunction
    env_vars_string = "".join(
        [
            " --set{} {}={}".format(
                "-string" if item.set_string else "", item.key, item.value
            )
            for item in env_vars
        ]
    )
    return env_vars_string


def helm_extra_vars(
    version=None, config_yaml=None, env_vars=None, preserve=None
):
    """Centralise obtaining extra variables for our helm_install and/or helm_upgrade

    Args:
        version (str): Which Chart version do we wish to install?
        config_yaml (str, Iterable): Values file(s) to override defaults.
        env_vars (Iterable): Environmental variables we wish to store in Helm.
        preserve (Iterable): Set of secrets we wish to get data from to assign to the Helm Chart.


    Returns:
        str: String of Chart version, values files, environmental variables,
    """
    # Get Helm Env-Vars
    extra_vars_string = ""
    if version:
        extra_vars_string += f" --version {version}"
    if config_yaml:
        if isinstance(config_yaml, (str, bytes)):
            config_yaml = (config_yaml,)
        if isinstance(config_yaml, (list, tuple)):
            extra_vars_string += " -f " + " -f ".join(config_yaml)
        else:
            raise ValueError("'config_yaml' variable should be a string, tuple or list")
    if env_vars:
        extra_vars_string += helm_env_vars(env_vars)
    if preserve:
        extra_vars_string += helm_preserve(preserve)
    return extra_vars_string


def helm_install(repo, app, release, namespace, extra_vars=""):
    """Install Helm chart.

    Args:
        repo (str): Repository or folder from which to install Helm chart.
        app (str): Helm application name.
        release (str): Release name on K8S.
        namespace (str): Namespace where to deploy Helm Chart.
        extra_vars (str): Extra variables for Helm including version, values files and environmental variables.

    """
    ls_res, _ = execute(f"helm status {release}")

    if not ls_res:
        command = f"helm install {repo}/{app} -n {release} --namespace {namespace}"
        command += extra_vars
        # Execute
        execute(command)


def helm_upgrade(repo, app, release, extra_vars=""):
    """Upgrade Helm chart.

    Args:
        repo (str): Repository or folder from which to install Helm chart.
        app (str): Helm application name.
        release (str): Release name on K8S.
        extra_vars (str): Extra variables for Helm including version, values files and environmental variables.

    """
    ls_res, _ = execute(f"helm status {release}")

    if ls_res:
        command = f"helm upgrade {release} {repo}/{app}"

        command += extra_vars or ""
        # Execute
        execute(command)
    else:
        raise Exception("Cannot update a Helm release that is not running")
