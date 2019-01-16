import glob
import shutil
from collections import namedtuple
from os import path, chdir, getcwd, listdir, makedirs

from nephos.fabric.utils import credentials_secret, crypto_secret, get_pod
from nephos.helpers.k8s import ingress_read, secret_from_file
from nephos.helpers.misc import execute, execute_until_success

PWD = getcwd()
CryptoInfo = namedtuple('CryptoInfo', ('secret_type', 'subfolder', 'key', 'required'))


# CA Helpers
def register_node(namespace, ca, node_type, username, password, verbose=False):
    # Get CA
    ca_exec = get_pod(namespace=namespace, release=ca, app='hlf-ca', verbose=verbose)
    # Check if Orderer is registered with the relevant CA
    ord_id = ca_exec.execute(
        'fabric-ca-client identity list --id {id}'.format(id=username))
    # Registered if needed
    if not ord_id:
        ca_exec.execute(
            'fabric-ca-client register --id.name {id} --id.secret {pw} --id.type {type}'.format(
                id=username, pw=password, type=node_type))


def enroll_node(opts, ca, username, password, verbose=False):
    dir_config = opts['core']['dir_config']
    ingress_urls = ingress_read(ca + '-hlf-ca', namespace=opts['core']['namespace'], verbose=verbose)
    msp_dir = '{}_MSP'.format(username)
    msp_path = path.join(dir_config, msp_dir)
    if not path.isdir(msp_path):
        # Enroll
        command = ('FABRIC_CA_CLIENT_HOME={dir} fabric-ca-client enroll ' +
                   '-u https://{username}:{password}@{ingress} -M {msp_dir} ' +
                   '--tls.certfiles {ca_server_tls}').format(
            dir=dir_config,
            username=username,
            password=password,
            ingress=ingress_urls[0],
            msp_dir=msp_dir,
            ca_server_tls=path.abspath(opts['cas'][ca]['tls_cert']))
        execute_until_success(command)
    return msp_path


def create_admin(opts, msp_name, verbose=False):
    dir_config = opts['core']['dir_config']
    msp_values = opts['msps'][msp_name]
    ca_values = opts['cas'][msp_values['ca']]

    # TODO: Refactor this into its own function
    ca_name = msp_values['ca']

    # Obtain CA pod
    pod_exec = get_pod(namespace=opts['core']['namespace'], release=ca_name, app='hlf-ca', verbose=verbose)

    # Get CA ingress
    ingress_urls = ingress_read(ca_name + '-hlf-ca', namespace=opts['core']['namespace'], verbose=verbose)
    ca_ingress = ingress_urls[0]

    # Register the Organisation with the CAs
    admin_id = pod_exec.execute(
        ('fabric-ca-client identity list --id {id}'
         ).format(id=msp_values['org_admin']))

    # If we cannot find the identity, we must create it
    if not admin_id:
        pod_exec.execute(
            ("fabric-ca-client register --id.name {id} --id.secret {pw} --id.attrs 'admin=true:ecert'"
             ).format(id=msp_values['org_admin'], pw=msp_values['org_adminpw']))

    # If our keystore does not exist or is empty, we need to enroll the identity...
    keystore = path.join(dir_config, msp_name, 'keystore')
    if not path.isdir(keystore) or not listdir(keystore):
        execute(
            ('FABRIC_CA_CLIENT_HOME={dir} fabric-ca-client enroll ' +
             '-u https://{id}:{pw}@{ingress} -M {msp_dir} --tls.certfiles {ca_server_tls}').format(
                dir=dir_config, id=msp_values['org_admin'], pw=msp_values['org_adminpw'],
                ingress=ca_ingress, msp_dir=msp_name,
                ca_server_tls=ca_values['tls_cert']
            ), verbose=verbose)


def admin_creds(opts, msp_name, verbose=False):
    msp_values = opts['msps'][msp_name]
    secret_data = credentials_secret(msp_values['org_admincred'], opts['core']['namespace'],
                                     username=msp_values['org_admin'], password=msp_values.get('org_adminpw'),
                                     verbose=verbose)
    msp_values['org_adminpw'] = secret_data['CA_PASSWORD']


def msp_secrets(opts, msp_name, verbose=False):
    # Relevant variables
    namespace = opts['core']['namespace']
    dir_config = opts['core']['dir_config']
    msp_values = opts['msps'][msp_name]

    # Copy cert to admincerts
    signcert = path.join(dir_config, msp_name, 'signcerts', 'cert.pem')
    admincert = path.join(dir_config, msp_name, 'admincerts', 'cert.pem')
    if not path.isfile(admincert):
        admin_dir = path.split(admincert)[0]
        if not path.isdir(admin_dir):
            makedirs(admin_dir)
        shutil.copy(signcert, admincert)

    # AdminCert
    secret_from_file(secret=msp_values['org_admincert'], namespace=namespace, key='cert.pem', filename=admincert,
                     verbose=verbose)

    # AdminKey
    adminkey = glob.glob(path.join(dir_config, msp_name, 'keystore', '*_sk'))[0]
    secret_from_file(secret=msp_values['org_adminkey'], namespace=namespace, key='key.pem', filename=adminkey,
                     verbose=verbose)


def admin_msp(opts, msp_name, verbose=False):
    # Get/set credentials
    admin_creds(opts, msp_name, verbose=verbose)

    # Crypto material for Admin
    create_admin(opts, msp_name, verbose=verbose)

    # Setup MSP secrets
    msp_secrets(opts, msp_name, verbose=verbose)


# General helpers
def crypto_to_secrets(namespace, msp_path, user, verbose=False):
    # Secrets
    crypto_info = [
        CryptoInfo('idcert', 'signcerts', 'cert.pem', True),
        CryptoInfo('idkey', 'keystore', 'key.pem', True),
        CryptoInfo('cacert', 'cacerts', 'cacert.pem', True),
        CryptoInfo('caintcert', 'intermediatecerts', 'intermediatecacert.pem', False)
    ]
    for item in crypto_info:
        secret_name = 'hlf--{user}-{type}'.format(user=user, type=item.secret_type)
        file_path = path.join(msp_path, item.subfolder)
        try:
            crypto_secret(secret_name,
                          namespace,
                          file_path=file_path,
                          key=item.key,
                          verbose=verbose)
        except Exception as error:
            if item.required:
                raise Exception(error)
            else:
                print('No {} found, so secret "{}" was not created'.format(file_path, secret_name))


# TODO: Create single function to enroll/register, separate from loop
def setup_nodes(opts, node_type, verbose=False):
    nodes = opts[node_type + 's']
    msp_values = opts['msps'][nodes['msp']]
    for release in nodes['names']:
        # Create secret with Orderer credentials
        secret_name = 'hlf--{}-cred'.format(release)
        secret_data = credentials_secret(secret_name, opts['core']['namespace'],
                                         username=release,
                                         verbose=verbose)
        # Register node
        register_node(opts['core']['namespace'], msp_values['ca'],
                      node_type, secret_data['CA_USERNAME'], secret_data['CA_PASSWORD'],
                      verbose=verbose)
        # Enroll node
        msp_path = enroll_node(opts, msp_values['ca'],
                               secret_data['CA_USERNAME'], secret_data['CA_PASSWORD'],
                               verbose=verbose)
        # Secrets
        crypto_to_secrets(namespace=opts['core']['namespace'], msp_path=msp_path, user=release, verbose=verbose)


# ConfigTxGen helpers
def genesis_block(opts, verbose=False):
    # Change to blockchain materials directory
    chdir(opts['core']['dir_config'])
    # Create the genesis block
    if not path.exists('genesis.block'):
        # Genesis block creation and storage
        execute(
            'configtxgen -profile OrdererGenesis -outputBlock genesis.block',
            verbose=verbose)
    else:
        print('genesis.block already exists')
    # Create the genesis block secret
    secret_from_file(secret=opts['orderers']['secret_genesis'], namespace=opts['core']['namespace'],
                     key='genesis.block', filename='genesis.block', verbose=verbose)
    # Return to original directory
    chdir(PWD)


def channel_tx(opts, verbose=False):
    # Change to blockchain materials directory
    chdir(opts['core']['dir_config'])
    # Create Channel Tx
    channel_file = '{channel}.tx'.format(channel=opts['peers']['channel_name'])
    if not path.exists(channel_file):
        # Channel transaction creation and storage
        execute(
            'configtxgen -profile {channel_profile} -channelID {channel} -outputCreateChannelTx {channel_file}'.format(
                channel_profile=opts['peers']['channel_profile'],
                channel=opts['peers']['channel_name'],
                channel_file=channel_file
            ),
            verbose=verbose)
    else:
        print('{channel}.tx already exists'.format(channel=opts['peers']['channel_name']))
    # Create the channel transaction secret
    secret_from_file(secret=opts['peers']['secret_channel'], namespace=opts['core']['namespace'],
                     key=channel_file, filename=channel_file, verbose=verbose)
    # Return to original directory
    chdir(PWD)
