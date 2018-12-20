from __future__ import print_function

from collections import namedtuple
from os import path
from time import sleep

from blessings import Terminal

from nephos.helpers.k8s import secret_read
from nephos.helpers.misc import execute

t = Terminal()

HelmPreserve = namedtuple('HelmPreserve', ('secret_name', 'data_item', 'values_path'))
# noinspection PyArgumentList
HelmSet = namedtuple('HelmSet', ('key', 'value', 'set_string'), defaults=(False,))

CURRENT_DIR = path.abspath(path.split(__file__)[0])


# TODO: Rename name to 'release'
def helm_check(app, name, namespace, pod_num=None):
    print(t.yellow('Ensuring that all pods are running '))
    running = False
    first_pass = True
    while not running:
        # TODO: Best to generate a function that checks app state
        states_list = execute(
            'kubectl get pods -n {ns} -l "app={app},release={name}" -o jsonpath="{{.items[*].status.phase}}"'.format(
                app=app, name=name, ns=namespace
            ), show_command=first_pass).split()
        # Let us also check the number of pods we have
        pod_list = execute(
            'kubectl get pods -n {ns} -l "app={app},release={name}" -o jsonpath="{{.items[*].metadata.name}}"'.format(
                app=app, name=name, ns=namespace
            ), show_command=first_pass).split()
        first_pass = False
        # We keep checking the state of the pods until they are running
        states = set(states_list)
        if len(states) == 1 and 'Running' in states and (pod_num is None or len(pod_list) == pod_num):
            print(t.green('All pods in {} are running'.format(name)))
            running = True
        else:
            print(t.red('.'), end='', flush=True)
            sleep(15)


# TODO: Separate the Helm helpers into a separate script
# Initialise helm
def helm_init():
    res = execute('helm list')
    if res is not None:
        print(t.green('Helm is already installed!'))
    else:
        execute('kubectl create -f {}/../../helm-rbac.yaml'.format(CURRENT_DIR))
        execute('helm init --service-account tiller')
        # Fix issue with automountServiceToken
        res = execute('kubectl -n kube-system get deployment tiller-deploy ' +
                      '-o jsonpath="{.spec.template.spec.automountServiceAccountToken}"')
        if res == 'false':
            execute("kubectl -n kube-system patch deployment tiller-deploy " +
                    "-p '{\"spec\": {\"template\": {\"spec\": {\"automountServiceAccountToken\": true}}}}'")
        # We keep checking the state of helm until everything is running
        running = False
        while not running:
            res = execute('helm list')
            if res is not None:
                running = True
            else:
                print(t.red('.'), end='', flush=True)
                sleep(15)


# General function to check if a release exists and install it
# TODO: Rename name to release
def helm_install(repo, app, name, namespace, config_yaml=None, env_vars=None, verbose=False, pod_num=1):
    ls_res = execute('helm status {name}'.format(
        name=name
    ))

    # TODO: Refactor this into separate helper function
    if not env_vars:
        env_vars = []
    else:
        env_vars = list(env_vars)
        for i, item in enumerate(env_vars):
            if isinstance(item, tuple):
                item = HelmSet(*item)
            elif not isinstance(item, HelmSet):
                raise TypeError('Items in env_vars array must be HelmSet named tuples')
            env_vars[i] = item

    if not ls_res:
        command = 'helm install {repo}/{app} -n {name} --namespace {ns}'.format(
            app=app, name=name, ns=namespace, repo=repo
        )
        if config_yaml:
            command += ' -f {}'.format(config_yaml)
        # Environmental variables
        env_vars_string = ''.join(
            [' --set{} {}={}'.format('-string' if item.set_string else '',
                                     item.key,
                                     item.value)
             for item in env_vars]
        )
        command += env_vars_string
        # Execute
        execute(command, verbose=verbose)
    helm_check(app, name, namespace, pod_num)


def helm_upgrade(repo, app, name, namespace, config_yaml=None, env_vars=None, preserve=None, verbose=False, pod_num=1):
    ls_res = execute('helm status {name}'.format(
        name=name
    ))

    # TODO: Refactor this into separate helper function
    if not env_vars:
        env_vars = []
    else:
        env_vars = list(env_vars)
        for i, item in enumerate(env_vars):
            if isinstance(item, tuple):
                item = HelmSet(*item)
            elif not isinstance(item, HelmSet):
                raise TypeError('Items in env_vars array must be HelmSet named tuples')
            env_vars[i] = item

    # Any data we need to preserve during upgrade?
    if preserve:
        for item in preserve:
            if isinstance(item, tuple):
                item = HelmPreserve(*item)
            elif not isinstance(item, HelmPreserve):
                raise TypeError('Items in preserve array must be HelmPerserve named tuples')
            secret_data = secret_read(item.secret_name, namespace, verbose=verbose)
            env_vars.append(HelmSet(item.values_path, secret_data[item.data_item]))

    if ls_res:
        command = 'helm upgrade {name} {repo}/{app}'.format(
            app=app, name=name, repo=repo
        )
        if config_yaml:
            command += ' -f {}'.format(config_yaml)
        # Environmental variables
        env_vars_string = ''.join(
            [' --set{} {}={}'.format('-string' if item.set_string else '',
                                     item.key,
                                     item.value)
             for item in env_vars]
        )
        command += env_vars_string
        # Execute
        execute(command, verbose=verbose)
    else:
        raise Exception('Cannot update a Helm release that is not running')
    helm_check(app, name, namespace, pod_num)
