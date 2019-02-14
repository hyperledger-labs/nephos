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

from kubernetes.client.rest import ApiException

from nephos.composer.connection_template import json_ct
from nephos.fabric.crypto import admin_creds
from nephos.fabric.utils import get_pod
from nephos.fabric.settings import get_namespace
from nephos.helpers.helm import helm_install, helm_upgrade
from nephos.helpers.k8s import (
    get_app_info,
    cm_create,
    cm_read,
    ingress_read,
    secret_from_file,
)


def get_composer_data(opts, verbose=False):
    """Get Composer deployment data.

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. False by default.

    Returns:
        dict: Data related to the Composer deployment (URI & API key)
    """
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    composer_name = opts["composer"]["name"] + "-hl-composer-rest"
    data = get_app_info(
        peer_namespace,
        composer_name,
        composer_name,
        secret_key="COMPOSER_APIKEY",
        verbose=verbose,
    )
    return data


# TODO: This is highly complex, we can probably simplify
def composer_connection(opts, verbose=False):
    """Composer connection setup.

    This creates a ConfigMap on K8S with the Hyperledger Composer connection.

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. Verbosity. False by default.
    """
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    ord_namespace = get_namespace(opts, opts["orderers"]["msp"])
    # TODO: This could be a single function
    peer_msp = opts["peers"]["msp"]
    peer_ca = opts["msps"][peer_msp]["ca"]
    ca_namespace = opts["cas"][peer_ca]["namespace"]
    ingress_urls = ingress_read(
        peer_ca + "-hlf-ca", namespace=ca_namespace, verbose=verbose
    )
    peer_ca_url = ingress_urls[0]
    try:
        cm_read(opts["composer"]["secret_connection"], peer_namespace, verbose=verbose)
    except ApiException:
        # Set up connection.json
        # TODO: Improve json_ct to work directly with opts structure
        cm_data = {
            "connection.json": json_ct(
                opts["peers"]["names"],
                opts["orderers"]["names"],
                [
                    peer + "-hlf-peer.{ns}.svc.cluster.local".format(ns=peer_namespace)
                    for peer in opts["peers"]["names"]
                ],
                [
                    orderer + "-hlf-ord.{ns}.svc.cluster.local".format(ns=ord_namespace)
                    for orderer in opts["orderers"]["names"]
                ],
                peer_ca,
                peer_ca_url,
                "AidTech",
                None,
                peer_msp,
                opts["peers"]["channel_name"],
            )
        }
        cm_create(peer_namespace, opts["composer"]["secret_connection"], cm_data)


def deploy_composer(opts, upgrade=False, verbose=False):
    """Deploy Hyperledger Composer on K8S.

    We use the hl-composer Helm chart as a basis to deploying Composer
    on K8S. Please note that Composer is unmaintained and may eventually
    be deprecated from this repository as we migrate to raw Fabric.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    # Ensure BNA exists
    secret_from_file(
        secret=opts["composer"]["secret_bna"], namespace=peer_namespace, verbose=verbose
    )
    composer_connection(opts, verbose=verbose)

    # Start Composer
    if not upgrade:
        helm_install(
            opts["core"]["chart_repo"],
            "hl-composer",
            opts["composer"]["name"],
            peer_namespace,
            pod_num=3,
            config_yaml="{dir}/hl-composer/{release}.yaml".format(
                dir=opts["core"]["dir_values"], release=opts["composer"]["name"]
            ),
            verbose=verbose,
        )
    else:
        # TODO: Implement upgrade: set $CA_USERNAME and $CA_PASSWORD
        pass


def setup_admin(opts, verbose=False):
    """Setup the Peer Admin for Hyperledger Composer.

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. False by default.
    """
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    hlc_cli_ex = get_pod(
        peer_namespace, opts["composer"]["name"], "hl-composer", verbose=verbose
    )

    # Set up the PeerAdmin card
    ls_res, _ = hlc_cli_ex.execute("composer card list --card PeerAdmin@hlfv1")

    if not ls_res:
        hlc_cli_ex.execute(
            (
                "composer card create "
                + "-p /hl_config/hlc-connection/connection.json "
                + "-u PeerAdmin -c /hl_config/admin/signcerts/cert.pem "
                + "-k /hl_config/admin/keystore/key.pem "
                + " -r PeerAdmin -r ChannelAdmin "
                + "--file /home/composer/PeerAdmin@hlfv1"
            )
        )
        hlc_cli_ex.execute(
            "composer card import " + "--file /home/composer/PeerAdmin@hlfv1.card"
        )


def install_network(opts, verbose=False):
    """Install Hyperledger Composer network.

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. False by default.
    """
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    hlc_cli_ex = get_pod(
        peer_namespace, opts["composer"]["name"], "hl-composer", verbose=verbose
    )

    # Install network
    # TODO: Getting BNA could be a helper function
    bna, _ = hlc_cli_ex.execute("ls /hl_config/blockchain_network")
    bna_name, bna_rem = bna.split("_")
    bna_version, _ = bna_rem.split(".bna")
    # TODO: This could be a single function
    peer_msp = opts["peers"]["msp"]
    bna_admin = opts["msps"][peer_msp]["org_admin"]
    admin_creds(opts, peer_msp, verbose=verbose)
    bna_pw = opts["msps"][peer_msp]["org_adminpw"]

    ls_res, _ = hlc_cli_ex.execute(
        "composer card list --card {bna_admin}@{bna_name}".format(
            bna_admin=bna_admin, bna_name=bna_name
        )
    )

    if not ls_res:
        hlc_cli_ex.execute(
            (
                "composer network install --card PeerAdmin@hlfv1 "
                + "--archiveFile /hl_config/blockchain_network/{bna}"
            ).format(bna=bna)
        )
        hlc_cli_ex.execute(
            (
                "composer network start "
                + "--card PeerAdmin@hlfv1 "
                + "--networkName {bna_name} --networkVersion {bna_version} "
                + "--networkAdmin {bna_admin} --networkAdminEnrollSecret {bna_pw}"
            ).format(
                bna_name=bna_name,
                bna_version=bna_version,
                bna_admin=bna_admin,
                bna_pw=bna_pw,
            )
        )
        hlc_cli_ex.execute(
            "composer card import --file {bna_admin}@{bna_name}.card".format(
                bna_admin=bna_admin, bna_name=bna_name
            )
        )

    hlc_cli_ex.execute(
        "composer network ping --card {bna_admin}@{bna_name}".format(
            bna_admin=bna_admin, bna_name=bna_name
        )
    )
