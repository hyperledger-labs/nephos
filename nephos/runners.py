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

from nephos.fabric.ca import setup_ca
from nephos.fabric.crypto import admin_msp, genesis_block, channel_tx, setup_nodes
from nephos.fabric.ord import setup_ord
from nephos.fabric.peer import setup_peer, setup_channel
from nephos.composer.install import deploy_composer, install_network, setup_admin
from nephos.composer.upgrade import upgrade_network


def runner_ca(opts, upgrade=False, verbose=False):
    """Deploy CAs.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    if opts["cas"]:
        setup_ca(opts, upgrade=upgrade, verbose=verbose)
    else:
        print("No CAs defined in Nephos settings, ignoring CA setup")


def runner_composer(opts, upgrade=False, verbose=False):
    """Deploy Hyperledger Composer.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    deploy_composer(opts, upgrade=upgrade, verbose=verbose)
    setup_admin(opts, verbose=verbose)
    install_network(opts, verbose=verbose)


def runner_composer_up(opts, verbose=False):
    """Upgrade Hyperledger Composer network (experimental).

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. False by default.
    """
    upgrade_network(opts, verbose=verbose)


def runner_crypto(opts, verbose=False):
    """Create Crypto-material by either using CAs or save Cryptogen material.

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. False by default.
    """
    # TODO: Limited by the fact that we manually specify MSPs
    # Set up Admin MSPs
    admin_msp(opts, opts["orderers"]["msp"], verbose=verbose)
    admin_msp(opts, opts["peers"]["msp"], verbose=verbose)
    # Genesis & Channel
    genesis_block(opts, verbose=verbose)
    # TODO: We currently only support a single channel
    channel_tx(opts, verbose=verbose)
    # Setup node MSPs
    setup_nodes(opts, "orderer", verbose=verbose)
    setup_nodes(opts, "peer", verbose=verbose)


def runner_deploy(opts, upgrade=False, verbose=False):
    """Deploy end-to-end deployment of Hyperledger Fabric and Composer.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    # Fabric
    runner_fabric(opts, upgrade=upgrade, verbose=verbose)
    # Composer
    runner_composer(opts, upgrade=upgrade, verbose=verbose)


def runner_fabric(opts, upgrade=False, verbose=False):
    """Deploy Hyperledger Fabric, including CAs/Cryptogen, Orderers and Peers.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    # Setup CA
    runner_ca(opts, upgrade=upgrade, verbose=verbose)
    # Crypto material
    runner_crypto(opts, verbose=verbose)
    # Orderers
    runner_orderer(opts, upgrade=upgrade, verbose=verbose)
    # Peers
    runner_peer(opts, upgrade=upgrade, verbose=verbose)


def runner_orderer(opts, upgrade=False, verbose=False):
    """Deploy Hyperledger Fabric Orderers.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    setup_ord(opts, upgrade=upgrade, verbose=verbose)


def runner_peer(opts, upgrade=False, verbose=False):
    """Deploy Hyperledger Fabric Peers.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    setup_peer(opts, upgrade=upgrade, verbose=verbose)
    setup_channel(opts, verbose=verbose)
