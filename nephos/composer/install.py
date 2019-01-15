from kubernetes.client.rest import ApiException


from nephos.composer.connection_template import json_ct
from nephos.fabric.utils import get_pod
from nephos.fabric.crypto import admin_creds
from nephos.helpers.helm import helm_install, helm_upgrade
from nephos.helpers.k8s import (get_app_info,
                                cm_create, cm_read, ingress_read, secret_from_file)


def get_composer_data(opts, verbose=False):
    composer_name = opts['composer']['name'] + '-hl-composer-rest'
    data = get_app_info(opts['core']['namespace'], composer_name, composer_name,
                        secret_key='COMPOSER_APIKEY', verbose=verbose)
    return data


def composer_connection(opts, verbose=False):
    # TODO: This could be a single function
    peer_ca = opts['peers']['ca']
    peer_ca_msp = opts['cas'][peer_ca]['msp']
    ingress_urls = ingress_read(peer_ca + '-hlf-ca', namespace=opts['core']['namespace'], verbose=verbose)
    peer_ca_url = ingress_urls[0]
    try:
        cm_read(opts['composer']['secret_connection'], opts['core']['namespace'], verbose=verbose)
    except ApiException:
        # Set up connection.json
        # TODO: Improve json_ct to work directly with opts structure
        cm_data = {'connection.json': json_ct(
            opts['peers']['names'],
            opts['orderers']['names'],
            [peer + '-hlf-peer.{ns}.svc.cluster.local'.format(ns=opts['core']['namespace']) for peer in
             opts['peers']['names']],
            [orderer + '-hlf-ord.{ns}.svc.cluster.local'.format(ns=opts['core']['namespace']) for orderer in
             opts['orderers']['names']],
            peer_ca,
            peer_ca_url,
            'AidTech',
            None,
            peer_ca_msp,
            opts['peers']['channel_name']
        )}
        cm_create(opts['core']['namespace'], opts['composer']['secret_connection'], cm_data)


def deploy_composer(opts, upgrade=False, verbose=False):
    # Ensure BNA exists
    secret_from_file(secret=opts['composer']['secret_bna'], namespace=opts['core']['namespace'],
                     verbose=verbose)
    composer_connection(opts, verbose=verbose)

    # Start Composer
    if not upgrade:
        helm_install(opts['core']['chart_repo'], 'hl-composer', opts['composer']['name'], opts['core']['namespace'],
                     pod_num=3,
                     config_yaml='{dir}/hl-composer/{release}.yaml'.format(
                         dir=opts['core']['dir_values'], release=opts['composer']['name']),
                     verbose=verbose)
    else:
        # TODO: Implement upgrade: set $CA_USERNAME and $CA_PASSWORD
        pass


def setup_admin(opts, verbose=False):
    hlc_cli_ex = get_pod(opts['core']['namespace'], opts['composer']['name'], 'hl-composer', verbose=verbose)

    # Set up the PeerAdmin card
    ls_res = hlc_cli_ex.execute('composer card list --card PeerAdmin@hlfv1')

    if not ls_res:
        hlc_cli_ex.execute(
            ('composer card create ' +
             '-p /hl_config/hlc-connection/connection.json ' +
             '-u PeerAdmin -c /hl_config/admin/signcerts/cert.pem ' +
             '-k /hl_config/admin/keystore/key.pem ' +
             ' -r PeerAdmin -r ChannelAdmin ' +
             '--file /home/composer/PeerAdmin@hlfv1'))
        hlc_cli_ex.execute(
            'composer card import ' +
            '--file /home/composer/PeerAdmin@hlfv1.card')


def install_network(opts, verbose=False):
    hlc_cli_ex = get_pod(opts['core']['namespace'], opts['composer']['name'], 'hl-composer', verbose=verbose)

    # Install network
    # TODO: Getting BNA could be a helper function
    bna = hlc_cli_ex.execute('ls /hl_config/blockchain_network')
    bna_name, bna_rem = bna.split('_')
    bna_version, _ = bna_rem.split('.bna')
    peer_ca = opts['peers']['ca']
    bna_admin = opts['cas'][peer_ca]['org_admin']
    admin_creds(opts['cas'][peer_ca], opts['core']['namespace'], verbose=verbose)
    bna_pw = opts['cas'][peer_ca]['org_adminpw']

    ls_res = hlc_cli_ex.execute('composer card list --card {bna_admin}@{bna_name}'.format(
            bna_admin=bna_admin, bna_name=bna_name))

    if not ls_res:
        hlc_cli_ex.execute(
            ('composer network install --card PeerAdmin@hlfv1 ' +
             '--archiveFile /hl_config/blockchain_network/{bna}').format(bna=bna))
        hlc_cli_ex.execute(
            ('composer network start ' +
             '--card PeerAdmin@hlfv1 ' +
             '--networkName {bna_name} --networkVersion {bna_version} ' +
             '--networkAdmin {bna_admin} --networkAdminEnrollSecret {bna_pw}').format(
                bna_name=bna_name, bna_version=bna_version, bna_admin=bna_admin, bna_pw=bna_pw
            ))
        hlc_cli_ex.execute('composer card import --file {bna_admin}@{bna_name}.card'.format(
                bna_admin=bna_admin, bna_name=bna_name))

    hlc_cli_ex.execute('composer network ping --card {bna_admin}@{bna_name}'.format(
        bna_admin=bna_admin, bna_name=bna_name))
