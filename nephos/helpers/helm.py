from __future__ import print_function

from collections import namedtuple
from os import path
from time import sleep

from blessings import Terminal

from nephos.helpers.k8s import pod_check, secret_read
from nephos.helpers.misc import execute

TERM = Terminal()

HelmPreserve = namedtuple("HelmPreserve", ("secret_name", "data_item", "values_path"))
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
    identifier = '-l "app={app},release={name}"'.format(
        app=app, name=release
    )
    pod_check(namespace, identifier, pod_num=pod_num)


def helm_init():
    """Initialise Helm on cluster, using RBAC."""
    res, _ = execute("helm list")
    if res is not None:
        print(TERM.green("Helm is already installed!"))
    else:
        execute("kubectl create -f {}/../extras/helm-rbac.yaml".format(CURRENT_DIR))
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
        env_vars (tuple): Environmental variables we wish to store in Helm.

    Returns:
        str: String containing variables to be set with Helm release.
    """
    if not env_vars:
        env_vars = []
    else:
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


def helm_preserve(namespace, preserve, verbose=False):
    """Convert secret data to a "--set" string for Helm deployments.

    Args:
        namespace (str): Namespace where preserved secrets are located.
        preserve (tuple): Set of secrets we wish to get data from to assign to the Helm Chart.
        verbose (bool): Verbosity. False by default.

    Returns:
        str: String containing variables to be set with Helm release.
    """

    # Any data we need to preserve during upgrade?
    if not preserve:
        return ""
    env_vars = []
    for item in preserve:
        if isinstance(item, tuple):
            item = HelmPreserve(*item)
        elif not isinstance(item, HelmPreserve):
            raise TypeError("Items in preserve array must be HelmPerserve named tuples")
        secret_data = secret_read(item.secret_name, namespace, verbose=verbose)
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


# TODO: Too many parameters - SQ Code Smell
# TODO: Cleanest way of fixing parameter issues is via a Helm class
def helm_install(
    repo,
    app,
    release,
    namespace,
    config_yaml=None,
    env_vars=None,
    version=None,
    verbose=False,
):
    """Install Helm chart.

    Args:
        repo (str): Repository or folder from which to install Helm chart.
        app (str): Helm application name.
        release (str): Release name on K8S.
        namespace (str): Namespace where to deploy Helm Chart.
        config_yaml (str): Values file to override defaults.
        env_vars (tuple): List of env vars we want to set.
        version (str): Which Chart version do we wish to install?
        verbose (bool): Verbosity. False by default.
    """
    ls_res, _ = execute("helm status {release}".format(release=release))

    # Get Helm Env-Vars
    env_vars_string = helm_env_vars(env_vars)

    if not ls_res:
        command = "helm install {repo}/{app} -n {name} --namespace {ns}".format(
            app=app, name=release, ns=namespace, repo=repo
        )
        if version:
            command += " --version {}".format(version)
        if config_yaml:
            command += " -f {}".format(config_yaml)
        command += env_vars_string
        # Execute
        execute(command, verbose=verbose)


# TODO: Too many parameters - SQ Code Smell
def helm_upgrade(
    repo,
    app,
    release,
    namespace,
    config_yaml=None,
    env_vars=None,
    preserve=None,
    version=None,
    verbose=False,
):
    """Upgrade Helm chart.

    Args:
        repo (str): Repository or folder from which to install Helm chart.
        app (str): Helm application name.
        release (str): Release name on K8S.
        namespace (str): Namespace where to deploy Helm Chart.
        config_yaml (str): Values file to override defaults.
        env_vars (tuple): Environmental variables we wish to store in Helm.
        preserve (tuple): Set of secrets we wish to get data from to assign to the Helm Chart.
        version (str): Which Chart version do we wish to install?
        verbose (bool): Verbosity. False by default.
    """
    ls_res, _ = execute("helm status {release}".format(release=release))

    # Get Helm Env-Vars
    env_vars_string = helm_env_vars(env_vars)
    env_vars_string += helm_preserve(namespace, preserve, verbose=verbose)

    if ls_res:
        command = "helm upgrade {name} {repo}/{app}".format(
            app=app, name=release, repo=repo
        )
        if version:
            command += " --version {}".format(version)
        if config_yaml:
            command += " -f {}".format(config_yaml)
        command += env_vars_string
        # Execute
        execute(command, verbose=verbose)
    else:
        raise Exception("Cannot update a Helm release that is not running")
