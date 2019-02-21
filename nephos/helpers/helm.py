from __future__ import print_function

from collections import namedtuple
from os import path
from time import sleep

from blessings import Terminal

from nephos.helpers.k8s import secret_read
from nephos.helpers.misc import execute

t = Terminal()

HelmPreserve = namedtuple("HelmPreserve", ("secret_name", "data_item", "values_path"))
# noinspection PyArgumentList
HelmSet = namedtuple("HelmSet", ("key", "value", "set_string"), defaults=(False,))

CURRENT_DIR = path.abspath(path.split(__file__)[0])


# TODO: We should be able to get the namespace from the Helm release...
# TODO: We should not need to specify pod number.
def helm_check(app, release, namespace, pod_num=None):
    """Check if a Helm release exists and is functional.

    Args:
        app (str): Helm application name.
        release (str): Release name on K8S.
        namespace (str): Namespace where Helm deployment is located.
        pod_num (int): Number of pods expected to exist in the release.
    """
    print(t.yellow("Ensuring that all pods are running "))
    running = False
    first_pass = True
    while not running:
        # TODO: Best to generate a function that checks app state
        states, _ = execute(
            'kubectl get pods -n {ns} -l "app={app},release={name}" -o jsonpath="{{.items[*].status.phase}}"'.format(
                app=app, name=release, ns=namespace
            ),
            show_command=first_pass,
        )
        states_list = states.split()
        # Let us also check the number of pods we have
        pods, _ = execute(
            'kubectl get pods -n {ns} -l "app={app},release={name}" -o jsonpath="{{.items[*].metadata.name}}"'.format(
                app=app, name=release, ns=namespace
            ),
            show_command=first_pass,
        )
        pod_list = pods.split()
        first_pass = False
        # We keep checking the state of the pods until they are running
        states = set(states_list)
        if (
            len(states) == 1
            and "Running" in states
            and (pod_num is None or len(pod_list) == pod_num)
        ):
            print(t.green("All pods in {} are running".format(release)))
            running = True
        else:
            print(t.red("."), end="", flush=True)
            sleep(15)


def helm_init():
    """Initialise Helm on cluster, using RBAC."""
    res, _ = execute("helm list")
    if res is not None:
        print(t.green("Helm is already installed!"))
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
                print(t.red("."), end="", flush=True)
                sleep(15)


# TODO: Probably split into separate sub-functions
def helm_env_vars(namespace, env_vars, preserve=None, verbose=False):
    """Convert environmental variables and secrets to a "--set" string for Helm deployments.

    Args:
        namespace (str): Namespace where preserved secrets are located.
        env_vars (list): Environmental variables we wish to store in Helm.
        preserve (list): Set of secrets we wish to get data from to assign to the Helm Chart.
        verbose (bool): Verbosity. False by default.

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

    # Any data we need to preserve during upgrade?
    if preserve:
        for item in preserve:
            if isinstance(item, tuple):
                item = HelmPreserve(*item)
            elif not isinstance(item, HelmPreserve):
                raise TypeError(
                    "Items in preserve array must be HelmPerserve named tuples"
                )
            secret_data = secret_read(item.secret_name, namespace, verbose=verbose)
            env_vars.append(HelmSet(item.values_path, secret_data[item.data_item]))
    # Environmental variables
    env_vars_string = "".join(
        [
            " --set{} {}={}".format(
                "-string" if item.set_string else "", item.key, item.value
            )
            for item in env_vars
        ]
    )
    return env_vars_string


def helm_install(
    repo,
    app,
    release,
    namespace,
    config_yaml=None,
    env_vars=None,
    verbose=False,
    pod_num=1,
):
    """Install Helm chart.

    Args:
        repo (str): Repository or folder from which to install Helm chart.
        app (str): Helm application name.
        release (str): Release name on K8S.
        namespace (str): Namespace where to deploy Helm Chart.
        config_yaml (str): Values file to ovverride defaults.
        env_vars (list): List of env vars we want to set.
        verbose (bool): Verbosity. False by default.
        pod_num (int): Number of pods we wish to have.
    """
    ls_res, _ = execute("helm status {release}".format(release=release))

    # Get Helm Env-Vars
    env_vars_string = helm_env_vars(namespace, env_vars, verbose=verbose)

    if not ls_res:
        command = "helm install {repo}/{app} -n {name} --namespace {ns}".format(
            app=app, name=release, ns=namespace, repo=repo
        )
        if config_yaml:
            command += " -f {}".format(config_yaml)
        command += env_vars_string
        # Execute
        execute(command, verbose=verbose)
    helm_check(app, release, namespace, pod_num)


def helm_upgrade(
    repo,
    app,
    release,
    namespace,
    config_yaml=None,
    env_vars=None,
    preserve=None,
    verbose=False,
    pod_num=1,
):
    """Upgrade Helm chart.

    Args:
        repo (str): Repository or folder from which to install Helm chart.
        app (str): Helm application name.
        release (str): Release name on K8S.
        namespace (str): Namespace where to deploy Helm Chart.
        config_yaml (str): Values file to ovverride defaults.
        env_vars (tuple): Environmental variables we wish to store in Helm.
        preserve (tuple): Set of secrets we wish to get data from to assign to the Helm Chart.
        verbose (bool): Verbosity. False by default.
        pod_num (int): Number of pods we wish to have.
    """
    ls_res, _ = execute("helm status {release}".format(release=release))

    # Get Helm Env-Vars
    env_vars_string = helm_env_vars(namespace, env_vars, preserve, verbose=verbose)

    if ls_res:
        command = "helm upgrade {name} {repo}/{app}".format(
            app=app, name=release, repo=repo
        )
        if config_yaml:
            command += " -f {}".format(config_yaml)
        command += env_vars_string
        # Execute
        execute(command, verbose=verbose)
    else:
        raise Exception("Cannot update a Helm release that is not running")
    helm_check(app, release, namespace, pod_num)
