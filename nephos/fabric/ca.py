import glob
from os import listdir, makedirs, path
import shutil
from time import sleep

from nephos.fabric.utils import credentials_secret, get_pod
from nephos.helpers.helm import HelmPreserve, helm_install, helm_upgrade
from nephos.helpers.k8s import (ingress_read, secret_from_file, secret_read)
from nephos.helpers.misc import execute, execute_until_success

CURRENT_DIR = path.abspath(path.split(__file__)[0])


# Core sub-functions
def ca_creds(ca_values, namespace, verbose=False):
    secret_data = credentials_secret(ca_values['org_admincred'], namespace,
                                     username=ca_values['org_admin'], password=ca_values.get('org_adminpw'),
                                     verbose=verbose)
    ca_values['org_adminpw'] = secret_data['CA_PASSWORD']


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


# TODO: Org admin registration/enrollment should be in the crypto.py section
def register_admin(pod_exec, ingress_host, dir_config, ca_values, verbose=False):
    # Register the Organisation with the CAs
    admin_id = pod_exec.execute(
        ('fabric-ca-client identity list --id {id}'
         ).format(id=ca_values['org_admin']))

    # If we cannot find the identity, we must create it
    if not admin_id:
        pod_exec.execute(
            ("fabric-ca-client register --id.name {id} --id.secret {pw} --id.attrs 'admin=true:ecert'"
             ).format(id=ca_values['org_admin'], pw=ca_values['org_adminpw']))

    # If our keystore does not exist or is empty, we need to enroll the identity...
    keystore = path.join(dir_config, ca_values['msp'], 'keystore')
    if not path.isdir(keystore) or not listdir(keystore):
        execute(
            ('FABRIC_CA_CLIENT_HOME={dir} fabric-ca-client enroll ' +
             '-u https://{id}:{pw}@{ingress} -M {msp_dir} --tls.certfiles {ca_server_tls}').format(
                dir=dir_config, id=ca_values['org_admin'], pw=ca_values['org_adminpw'],
                ingress=ingress_host, msp_dir=ca_values['msp'],
                ca_server_tls=ca_values['tls_cert']
            ), verbose=verbose)


def ca_secrets(ca_values, namespace, dir_config, verbose=False):
    # Copy cert to admincerts
    signcert = path.join(dir_config, ca_values['msp'], 'signcerts', 'cert.pem')
    admincert = path.join(dir_config, ca_values['msp'], 'admincerts', 'cert.pem')
    if not path.isfile(admincert):
        admin_dir = path.split(admincert)[0]
        if not path.isdir(admin_dir):
            makedirs(admin_dir)
        shutil.copy(signcert, admincert)

    # AdminCert
    secret_from_file(secret=ca_values['org_admincert'], namespace=namespace, key='cert.pem', filename=admincert,
                     verbose=verbose)

    # AdminKey
    adminkey = glob.glob(path.join(dir_config, ca_values['msp'], 'keystore', '*_sk'))[0]
    secret_from_file(secret=ca_values['org_adminkey'], namespace=namespace, key='key.pem', filename=adminkey,
                     verbose=verbose)


# Runner
def setup_ca(opts, upgrade=False, verbose=False):
    for ca_key, ca_values in opts['cas'].items():
        # Install Charts
        ca_chart(opts=opts, release=ca_key,
                 upgrade=upgrade, verbose=verbose)

        # Obtain CA pod
        pod_exec = get_pod(namespace=opts['core']['namespace'], release=ca_key, app='hlf-ca', verbose=verbose)

        ca_enroll(pod_exec)

        if 'msp' in ca_values:
            # Get/set credentials
            ca_creds(ca_values, namespace=opts['core']['namespace'], verbose=verbose)

            # Get CA Ingress and check it is running
            ingress_urls = ingress_read(ca_key + '-hlf-ca', namespace=opts['core']['namespace'], verbose=verbose)
            check_ca(ingress_host=ingress_urls[0], verbose=verbose)

            # Crypto material for Admin
            register_admin(pod_exec=pod_exec, ingress_host=ingress_urls[0],
                           dir_config=opts['core']['dir_config'], ca_values=ca_values,
                           verbose=verbose)

            ca_secrets(ca_values=ca_values,
                       namespace=opts['core']['namespace'], dir_config=opts['core']['dir_config'], verbose=verbose)
