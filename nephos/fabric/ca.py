from os import path
from time import sleep

from kubernetes.client.rest import ApiException
from nephos.fabric.utils import get_pod
from nephos.helpers.helm import HelmPreserve, helm_install, helm_upgrade
from nephos.helpers.k8s import (ingress_read, secret_read)
from nephos.helpers.misc import execute_until_success

CURRENT_DIR = path.abspath(path.split(__file__)[0])


# Core sub-functions
def ca_chart(opts, release, upgrade=False, verbose=False):
    values_dir = opts['core']['dir_values']
    repository = opts['core']['chart_repo']
    namespace = opts['core']['namespace']
    # PostgreSQL (Upgrades here are dangerous, deactivated by default)
    helm_install('stable', 'postgresql', '{}-pg'.format(release), namespace,
                 config_yaml='{dir}/postgres-ca/{name}-pg.yaml'.format(dir=values_dir, name=release),
                 verbose=verbose)
    psql_secret = secret_read('{}-pg-postgresql'.format(release), namespace,
                              verbose=verbose)
    # Different key depending of PostgreSQL version
    psql_password = psql_secret.get('postgres-password') or psql_secret['postgresql-password']
    env_vars = [('externalDatabase.password', psql_password)]
    # Fabric CA
    if not upgrade:
        helm_install(repository, 'hlf-ca', release, namespace,
                     config_yaml='{dir}/hlf-ca/{name}.yaml'.format(dir=values_dir, name=release),
                     env_vars=env_vars,
                     verbose=verbose)
    else:
        # TODO: Remove this try/catch once all CAs are updated
        try:
            preserve = (HelmPreserve('{}-hlf-ca'.format(release), 'CA_ADMIN', 'adminUsername'),
                        HelmPreserve('{}-hlf-ca'.format(release), 'CA_PASSWORD', 'adminPassword'))
            helm_upgrade(repository, 'hlf-ca', release, namespace,
                         config_yaml='{dir}/hlf-ca/{name}.yaml'.format(dir=values_dir, name=release),
                         env_vars=env_vars, preserve=preserve,
                         verbose=verbose)
        except:
            preserve = (HelmPreserve('{}-hlf-ca--ca'.format(release), 'CA_ADMIN', 'adminUsername'),
                        HelmPreserve('{}-hlf-ca--ca'.format(release), 'CA_PASSWORD', 'adminPassword'))
            helm_upgrade(repository, 'hlf-ca', release, namespace,
                         config_yaml='{dir}/hlf-ca/{name}.yaml'.format(dir=values_dir, name=release),
                         env_vars=env_vars, preserve=preserve,
                         verbose=verbose)


def ca_enroll(pod_exec):
    alive = False
    while not alive:
        res = pod_exec.logs()
        if 'Listening on' in res:
            alive = True
        else:
            sleep(15)
    # Enroll CA Admin if necessary
    ca_cert = pod_exec.execute(
        'cat /var/hyperledger/fabric-ca/msp/signcerts/cert.pem')
    if not ca_cert:
        pod_exec.execute(
            "bash -c 'fabric-ca-client enroll -d -u http://$CA_ADMIN:$CA_PASSWORD@$SERVICE_DNS:7054'")


def check_ca(ingress_host, verbose=False):
    # Check that CA ingress is operational
    command = 'curl https://{ingress}/cainfo'.format(ingress=ingress_host)
    execute_until_success(command, verbose=verbose)


# Runner
def setup_ca(opts, upgrade=False, verbose=False):
    for ca_name, ca_values in opts['cas'].items():
        # Install Charts
        ca_chart(opts=opts, release=ca_name,
                 upgrade=upgrade, verbose=verbose)

        # Obtain CA pod and Enroll
        pod_exec = get_pod(namespace=opts['core']['namespace'], release=ca_name, app='hlf-ca', verbose=verbose)
        ca_enroll(pod_exec)

        # Get CA Ingress and check it is running
        try:
            # Get ingress of CA
            ingress_urls = ingress_read(ca_name + '-hlf-ca', namespace=opts['core']['namespace'], verbose=verbose)
        except ApiException:
            print('No ingress found for CA')
            continue

        # Check the CA is running
        check_ca(ingress_host=ingress_urls[0], verbose=verbose)
