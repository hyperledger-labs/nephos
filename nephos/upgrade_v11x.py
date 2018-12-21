#! /usr/bin/env python

from collections import namedtuple
import os

import click
from kubernetes.client.rest import ApiException

from nephos.fabric.settings import load_config
from nephos.fabric.utils import get_pod
from nephos.fabric.ord import check_ord
from nephos.fabric.peer import check_peer
from nephos.helpers.helm import helm_upgrade
from nephos.helpers.k8s import ns_create, secret_read, secret_create

PWD = os.getcwd()
CryptoInfo = namedtuple('CryptoInfo', ('secret_type', 'subfolder', 'key', 'required'))

NODE_MAPPER = {'orderer': 'hlf-ord', 'peer': 'hlf-peer'}


def extract_credentials(opts, node_type, verbose=False):
    chart = NODE_MAPPER[node_type]
    # Loop over the nodes
    for release in opts[node_type + 's']['names']:
        secret_name = 'hlf--{}-cred'.format(release)
        try:
            secret_read(secret_name, opts['core']['namespace'])
            if verbose:
                print('{} secret already exists'.format(secret_name))
        except ApiException:
            # Obtain secret data from original chart secret
            original_data = secret_read('{}-{}'.format(release, chart), opts['core']['namespace'])
            # Create secret with Orderer credentials
            secret_data = {
                'CA_USERNAME': original_data['CA_USERNAME'],
                'CA_PASSWORD': original_data['CA_PASSWORD']
            }
            secret_create(secret_data, secret_name, opts['core']['namespace'], verbose=verbose)


def extract_crypto(opts, node_type, verbose=False):
    # Get chart type
    chart = NODE_MAPPER[node_type]
    for release in opts[node_type + 's']['names']:
        pod_ex = get_pod(opts['core']['namespace'], release, chart)
        # Secrets
        crypto_info = [
            CryptoInfo('idcert', 'signcerts', 'cert.pem', True),
            CryptoInfo('idkey', 'keystore', 'key.pem', True),
            CryptoInfo('cacert', 'cacerts', 'cacert.pem', True),
            CryptoInfo('caintcert', 'intermediatecerts', 'intermediatecacert.pem', False)
        ]
        for item in crypto_info:
            secret_name = 'hlf--{}-{}'.format(release, item.secret_type)
            try:
                secret_read(secret_name, opts['core']['namespace'])
                if verbose:
                    print('{} secret already exists'.format(secret_name))
            except ApiException:
                command = "bash -c 'ls /var/hyperledger/msp/{}' | wc -l".format(item.subfolder)
                file_num = pod_ex.execute(command)
                if file_num.strip() != '1':
                    if item.required:
                        raise ValueError('We should only have 1 file in each of these folders')
                    else:
                        print('Wrong number of files in {} directory'.format(item.subfolder))
                else:
                    command = "bash -c 'cat /var/hyperledger/msp/{}/*'".format(item.subfolder)
                    content = pod_ex.execute(command)
                    secret_data = {
                        item.key: content
                    }
                    secret_create(secret_data, secret_name, opts['core']['namespace'], verbose=verbose)


def upgrade_charts(opts, node_type, verbose=False):
    # Get chart type
    chart = NODE_MAPPER[node_type]
    for release in opts[node_type + 's']['names']:
        pod_ex = get_pod(opts['core']['namespace'], release, chart)
        res = pod_ex.execute('ls /var/hyperledger/msp_old')
        if not res:
            pod_ex.execute('mv /var/hyperledger/msp /var/hyperledger/msp_old')
        else:
            print('/var/hyperledger/msp_old already exists')
        config_yaml = '{dir}/{chart}/{name}.yaml'.format(
                         dir=opts['core']['dir_values'], chart=chart, name=release)
        helm_upgrade(opts['core']['chart_repo'], chart, release, opts['core']['namespace'],
                     config_yaml=config_yaml,
                     verbose=verbose)
        if node_type == 'orderer':
            check_ord(opts['core']['namespace'], release, verbose=verbose)
        elif node_type == 'peer':
            check_peer(opts['core']['namespace'], release, verbose=verbose)


@click.command()
@click.option('--settings_file', '-f', required=True, help='YAML file containing HLF options')
@click.option('--verbose/--quiet', '-v/-q', default=False)
def main(settings_file, verbose=False):  # pragma: no cover
    opts = load_config(settings_file)
    ns_create(opts['core']['namespace'], verbose=verbose)
    extract_credentials(opts, 'orderer', verbose=verbose)
    extract_credentials(opts, 'peer', verbose=verbose)
    extract_crypto(opts, 'orderer', verbose=verbose)
    extract_crypto(opts, 'peer', verbose=verbose)
    upgrade_charts(opts, 'orderer', verbose=verbose)
    upgrade_charts(opts, 'peer', verbose=verbose)


if __name__ == "__main__":  # pragma: no cover
    main()
