#   Copyright [2018] [Alejandro Vicente Grabovetsky via AID:Tech]
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at#
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import shutil
from collections import namedtuple
from glob import glob
from os import chdir, getcwd, listdir, makedirs
from os.path import abspath, exists, isfile, isdir, join, split
from time import sleep
import logging

from nephos.fabric.settings import get_namespace
from nephos.helpers.k8s import ns_create, ingress_read, secret_from_file
from nephos.helpers.misc import execute, execute_until_success
from nephos.fabric.utils import (
    get_msps,
    get_channels,
    get_peers,
    get_orderers,
    is_orderer_msp,
    credentials_secret,
    crypto_secret,
    get_helm_pod,
    get_secret_genesis
)

PWD = getcwd()
CryptoInfo = namedtuple("CryptoInfo", ("secret_type", "subfolder", "key", "required"))


# CA Helpers
def check_id(ca_namespace, ca, username):
    """

    Args:
        ca_namespace (str): K8S namespace where CA is located.
        ca (str): K8S release name of CA.
        username (str): Username for identity.

    Returns:
        bool: Does the ID exist?
    """
    # Get CA
    ca_exec = get_helm_pod(
        namespace=ca_namespace, release=ca, app="hlf-ca"
    )
    # Check if Orderer is registered with the relevant CA
    got_id = False
    while not got_id:
        ord_id, err = ca_exec.execute(
            f"fabric-ca-client identity list --id {username}"
        )
        if err:
            # Expected error (identity does not exist)
            if "no rows in result set" in err:
                got_id = True
            # Otherwise, unexpected error, we are having issues connecting to CA
            else:
                sleep(15)
        else:
            got_id = True
    return ord_id


def register_id(
    ca_namespace, ca, username, password, node_type="client", admin=False):
    """Register an ID with a Fabric Certificate Authority

    Args:
        ca_namespace (str): K8S namespace where CA is located.
        ca (str): K8S release name of CA.
        username (str): Username for identity.
        password (str): Password for identity.
        node_type (str): Node type for identity. "client" by default.
        admin (bool): Whether the identity is an admin. False by default.
    """
    # Get CA
    ord_id = check_id(ca_namespace, ca, username)
    # Registered if needed
    ca_exec = get_helm_pod(namespace=ca_namespace, release=ca, app="hlf-ca")
    if not ord_id:
        command = (
            "fabric-ca-client register --id.name {id} --id.secret {pw} --id.type {type}"
        )
        if admin:
            command += " --id.attrs 'admin=true:ecert'"
        registered_id = False
        while not registered_id:
            res, err = ca_exec.execute(
                command.format(id=username, pw=password, type=node_type)
            )
            if not err:
                registered_id = True
            # Otherwise, unexpected error, we are having issues connecting to CA
            else:
                sleep(15)


def enroll_id(opts, ca, username, password):
    """Enroll an ID with a Fabric Certificate Authority

    Args:
        opts (dict): Nephos options dict.
        ca (str): K8S release name of CA.
        username (str): Username for identity.
        password (str): Password for identity.

    Returns:
        str: Path of the MSP directory where cryptographic data is saved.

    """
    dir_crypto = opts["core"]["dir_crypto"]
    ca_namespace = get_namespace(opts, ca=ca)
    ingress_urls = ingress_read(ca + "-hlf-ca", namespace=ca_namespace)
    msp_dir = f"{username}_MSP"
    msp_path = join(dir_crypto, msp_dir)
    if not isdir(msp_path):
        # Enroll
        command = (
            f'FABRIC_CA_CLIENT_HOME={dir_crypto} fabric-ca-client enroll '
            + f'-u https://{username}:{password}@{ingress_urls[0]} -M {join(dir_crypto, msp_dir)} '
            + f'--tls.certfiles {abspath(opts["cas"][ca]["tls_cert"])}'
        )
        execute_until_success(command)
    return msp_path


def create_admin(opts, msp_name):
    """Create an admin identity.

    Args:
        opts (dict): Nephos options dict.
        msp_name (str): Name of Membership Service Provider.
    """
    dir_config = opts["core"]["dir_config"]
    dir_crypto = opts["core"]["dir_crypto"]
    msp_values = opts["msps"][msp_name]
    ca_values = opts["cas"][msp_values["ca"]]

    # TODO: Refactor this into its own function
    ca_name = msp_values["ca"]
    ca_namespace = get_namespace(opts, ca=ca_name)

    # Get CA ingress
    ingress_urls = ingress_read(
        ca_name + "-hlf-ca", namespace=ca_namespace)
    ca_ingress = ingress_urls[0]

    # Register the Organisation with the CAs
    register_id(
        ca_namespace,
        msp_values["ca"],
        msp_values["org_admin"],
        msp_values["org_adminpw"],
        admin=True,
    )

    # TODO: Can we reuse the Enroll function above?
    # If our keystore does not exist or is empty, we need to enroll the identity...
    keystore = join(dir_crypto, msp_name, "keystore")
    if not isdir(keystore) or not listdir(keystore):
        execute(
            (
                f"FABRIC_CA_CLIENT_HOME={dir_config} fabric-ca-client enroll "
                + f"-u https://{msp_values['org_admin']}:{msp_values['org_adminpw']}@{ca_ingress} "
                + f"-M {join(dir_crypto, msp_name)} --tls.certfiles {abspath(ca_values['tls_cert'])}"
            ),
        )


def admin_creds(opts, msp_name):
    """Get admin credentials and save them to Nephos options dict.

    Args:
        opts (dict): Nephos options dict.
        msp_name (str): Name of Membership Service Provider.
    """
    msp_namespace = get_namespace(opts, msp=msp_name)
    msp_values = opts["msps"][msp_name]

    admin_cred_secret = f"hlf--{msp_values['org_admin']}-admincred"
    secret_data = credentials_secret(
        admin_cred_secret,
        msp_namespace,
        username=msp_values["org_admin"],
        password=msp_values.get("org_adminpw"),
    )
    msp_values["org_adminpw"] = secret_data["CA_PASSWORD"]


# TODO: Rename to something more appropriate (e.g. copy_msp_file)
def copy_secret(from_dir, to_dir):
    """Copy single secret file from one directory to another.

    Args:
        from_dir (str): Source directory where file resides.
        to_dir (str): Destination directory for file.
    """
    from_list = glob(join(from_dir, "*"))
    if len(from_list) == 1:
        from_file = from_list[0]
    else:
        raise ValueError(
            f"from_dir contains {len(from_list)} files - {from_list}"
        )
    _, from_filename = split(from_file)
    to_file = join(to_dir, from_filename)
    if not isfile(to_file):
        if not isdir(to_dir):
            makedirs(to_dir)
        shutil.copy(from_file, to_file)


def msp_secrets(opts, msp_name):
    """Process MSP and convert it to a set of secrets.

    Args:
        opts (dict): Nephos options dict.
        msp_name (str): Name of Membership Service Provider.
    """
    # Relevant variables
    msp_namespace = get_namespace(opts, msp=msp_name)
    msp_values = opts["msps"][msp_name]
    if opts["cas"]:
        # If we have a CA, MSP was saved to dir_crypto
        msp_path = join(opts["core"]["dir_crypto"], msp_name)
    else:
        # Otherwise we are using Cryptogen
        glob_target = f"{opts['core']['dir_crypto']}/crypto-config/*Organizations/{msp_namespace}*/users/Admin*/msp"
        msp_path_list = glob(glob_target)
        if len(msp_path_list) == 1:
            msp_path = msp_path_list[0]
        else:
            raise ValueError(
                f"MSP path list length is {msp_path_list} - {msp_path_list}"
            )

    # Copy cert to admincerts
    copy_secret(join(msp_path, "signcerts"), join(msp_path, "admincerts"))

    # Create ID secrets from Admin MSP
    id_to_secrets(msp_namespace, msp_path, msp_values["org_admin"])

    # Create CA secrets from Admin MSP
    cacerts_to_secrets(msp_namespace, msp_path, msp_values["org_admin"])


def admin_msp(opts, msp_name):
    """Setup the admin MSP, by getting/setting credentials and creating/saving crypto-material.

    Args:
        opts (dict): Nephos options dict.
        msp_name (str): Name of Membership Service Provider.
    """
    admin_namespace = get_namespace(opts, msp_name)
    ns_create(admin_namespace)

    if opts["cas"]:
        # Get/set credentials (if we use a CA)
        admin_creds(opts, msp_name)
        # Crypto material for Admin
        create_admin(opts, msp_name)
    else:
        logging.info("No CAs defined in Nephos settings, ignoring Credentials")

    # Setup MSP secrets
    msp_secrets(opts, msp_name)


# General helpers
def item_to_secret(namespace, msp_path, username, item):
    """Save a single MSP crypto-material file as a K8S secret.

    Args:
        namespace (str): Namespace where secret will live.
        msp_path (str): Path to the Membership Service Provider crypto-material.
        username (str): Username for identity.
        item (CryptoInfo): Item containing cryptographic material information.
    """
    # Item in form CryptoInfo(name, subfolder, key, required)
    secret_name = f"hlf--{username}-{item.secret_type}"
    file_path = join(msp_path, item.subfolder)
    try:
        crypto_secret(secret_name, namespace, file_path=file_path, key=item.key)
    except Exception as error:
        if item.required:
            raise Exception(error)
        else:
            logging.warning(
                f'No {file_path} found, so secret "{secret_name}" was not created'
            )


def id_to_secrets(namespace, msp_path, username):
    """Convert Identity certificate and key to K8S secrets.

    Args:
        namespace (str): Namespace where secret will live.
        msp_path (str): Path to the Membership Service Provider crypto-material.
        username (str): Username for identity.
    """
    crypto_info = [
        CryptoInfo("idcert", "signcerts", "cert.pem", True),
        CryptoInfo("idkey", "keystore", "key.pem", True),
    ]
    for item in crypto_info:
        item_to_secret(namespace, msp_path, username, item)


def cacerts_to_secrets(namespace, msp_path, user):
    """Convert CA certificate to K8S secrets.

    Args:
        namespace (str): Namespace where secret will live.
        msp_path (str): Path to the Membership Service Provider crypto-material.
        username (str): Username for identity.
    """
    crypto_info = [
        CryptoInfo("cacert", "cacerts", "cacert.pem", True),
        CryptoInfo("caintcert", "intermediatecerts", "intermediatecacert.pem", False),
    ]
    for item in crypto_info:
        item_to_secret(namespace, msp_path, user, item)


def setup_id(opts, msp_name, release, id_type):
    """Setup single ID by registering, enrolling, and saving ID to K8S secrets.

    Args:
        opts (dict): Nephos options dict.
        msp_name (str): Name of Membership Service Provider.
        release (str): Name of release/node.
        id_type (str): Type of ID we use.
    """
    msp_values = opts["msps"][msp_name]
    node_namespace = get_namespace(opts, msp_name)
    if opts["cas"]:
        ca_namespace = get_namespace(opts, ca=opts["msps"][msp_name]["ca"])
        # Create secret with Orderer credentials
        secret_name = f"hlf--{release}-cred"
        secret_data = credentials_secret(
            secret_name, node_namespace, username=release
        )
        # Register node
        register_id(
            ca_namespace,
            msp_values["ca"],
            secret_data["CA_USERNAME"],
            secret_data["CA_PASSWORD"],
            id_type,
        )
        # Enroll node
        msp_path = enroll_id(
            opts,
            msp_values["ca"],
            secret_data["CA_USERNAME"],
            secret_data["CA_PASSWORD"],
        )
    else:
        # Otherwise we are using Cryptogen
        glob_target = f"{opts['core']['dir_crypto']}/crypto-config/{id_type}Organizations/{node_namespace}*/{id_type}s/{release}*/msp"
        msp_path_list = glob(glob_target)
        if len(msp_path_list) == 1:
            msp_path = msp_path_list[0]
        else:
            raise ValueError(
                f"MSP path list length is {msp_path_list} - {msp_path_list}"
            )
    # Secrets
    id_to_secrets(
        namespace=node_namespace, msp_path=msp_path, username=release
    )


# TODO: Rename to mention identities.
def setup_nodes(opts):
    """Setup identities for nodes.

    Args:
        opts (dict): Nephos options dict.
    """
    for msp in get_msps(opts=opts):
        for peer in get_peers(opts=opts, msp=msp):
            setup_id(opts, msp, peer, "peer")

    for msp in get_msps(opts=opts):
        for orderer in get_orderers(opts=opts, msp=msp):
            setup_id(opts, msp, orderer, "orderer")


# ConfigTxGen helpers
def genesis_block(opts):
    """Create and save Genesis Block to K8S.

    Args:
        opts (dict): Nephos options dict.
    """
    # Change to blockchain materials directory
    chdir(opts["core"]["dir_config"])
    # Create the genesis block
    genesis_key = "genesis.block"
    genesis_file = join(opts["core"]["dir_crypto"], genesis_key)
    if not exists(genesis_file):
        # Genesis block creation and storage
        execute(
            f"configtxgen -profile OrdererGenesis -outputBlock {genesis_file}",
        )
    else:
        logging.info(f"{genesis_file} already exists")

    for msp in get_msps(opts=opts):
        if not is_orderer_msp(opts=opts, msp=msp):
            continue
        ord_namespace = get_namespace(opts, msp=msp)
        # Create the genesis block secret
        secret_from_file(
            secret=get_secret_genesis(opts=opts),
            namespace=ord_namespace,
            key=genesis_key,
            filename=genesis_file,
        )
        # Return to original directory
    chdir(PWD)


def channel_tx(opts):
    """Create and save Channel Transaction to K8S.

    Args:
        opts (dict): Nephos options dict.
    """
    # Change to blockchain materials directory
    chdir(opts["core"]["dir_config"])
    # Create Channel Tx
    for channel in get_channels(opts):
        channel_key = f"{opts['channels'][channel]['channel_name']}.tx"
        channel_file = join(opts["core"]["dir_crypto"], channel_key)
        if not exists(channel_file):
            # Channel transaction creation and storage
            execute(
                f"configtxgen -profile {opts['channels'][channel]['channel_profile']} -channelID {opts['channels'][channel]['channel_name']} -outputCreateChannelTx {channel_file}",
            )
        else:
            logging.info(f"{channel_file} already exists")
        # Create the channel transaction secret
        for msp in get_msps(opts=opts):
            if msp not in opts["channels"][channel]["msps"]:
                continue
            peer_namespace = get_namespace(opts, msp=msp)
            secret_from_file(
                secret=opts['channels'][channel]["secret_channel"],
                namespace=peer_namespace,
                key=channel_key,
                filename=channel_file,
            )
            # Return to original directory
    chdir(PWD)
