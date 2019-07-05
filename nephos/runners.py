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
import logging

from nephos.fabric.ca import setup_ca
from nephos.fabric.crypto import admin_msp, genesis_block, channel_tx, setup_nodes
from nephos.fabric.ord import setup_ord
from nephos.fabric.peer import setup_peer, create_channel
from nephos.composer.install import deploy_composer, install_network, setup_admin
from nephos.composer.upgrade import upgrade_network
from nephos.fabric.utils import get_msps


def runner_ca(opts, upgrade=False):
    """Deploy CAs.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        
    """
    if opts["cas"]:
        setup_ca(opts, upgrade=upgrade)
    else:
        logging.warning("No CAs defined in Nephos settings, ignoring CA setup")


def runner_composer(opts, upgrade=False):
    """Deploy Hyperledger Composer.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        
    """
    deploy_composer(opts, upgrade=upgrade)
    setup_admin(opts)
    install_network(opts)


def runner_composer_up(opts):
    """Upgrade Hyperledger Composer network (experimental).

    Args:
        opts (dict): Nephos options dict.
        
    """
    upgrade_network(opts)


def runner_crypto(opts):
    """Create Crypto-material by either using CAs or save Cryptogen material.

    Args:
        opts (dict): Nephos options dict.
        
    """
    # Set up Admin MSPs
    for msp in get_msps(opts=opts):
        admin_msp(opts, msp)
    # Genesis & Channel
    genesis_block(opts)
    # TODO: We currently only support a single channel
    channel_tx(opts)
    # Setup node MSPs
    setup_nodes(opts)


def runner_deploy(opts, upgrade=False):
    """Deploy end-to-end deployment of Hyperledger Fabric and Composer.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        
    """
    # Fabric
    runner_fabric(opts, upgrade=upgrade)
    # Composer
    runner_composer(opts, upgrade=upgrade)


def runner_fabric(opts, upgrade=False):
    """Deploy Hyperledger Fabric, including CAs/Cryptogen, Orderers and Peers.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        
    """
    # Setup CA
    runner_ca(opts, upgrade=upgrade)
    # Crypto material
    runner_crypto(opts)
    # Orderers
    runner_orderer(opts, upgrade=upgrade)
    # Peers
    runner_peer(opts, upgrade=upgrade)


def runner_orderer(opts, upgrade=False):
    """Deploy Hyperledger Fabric Orderers.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        
    """
    setup_ord(opts, upgrade=upgrade)


def runner_peer(opts, upgrade=False):
    """Deploy Hyperledger Fabric Peers.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        
    """
    setup_peer(opts, upgrade=upgrade)
    create_channel(opts)
