from nephos.fabric.ca import setup_ca
from nephos.fabric.crypto import admin_msp, genesis_block, channel_tx, setup_nodes
from nephos.fabric.ord import setup_ord
from nephos.fabric.peer import setup_peer, setup_channel
from nephos.composer.install import deploy_composer, install_network, setup_admin


def runner_ca(opts, upgrade=False, verbose=False):
    setup_ca(opts, upgrade=upgrade, verbose=verbose)


def runner_composer(opts, upgrade=False, verbose=False):
    deploy_composer(opts, upgrade=upgrade, verbose=verbose)
    setup_admin(opts, verbose=verbose)
    install_network(opts, verbose=verbose)


def runner_crypto(opts, verbose=False):
    # Set up Admin MSPs
    admin_msp(opts, opts['orderers']['msp'], verbose=verbose)
    admin_msp(opts, opts['peers']['msp'], verbose=verbose)
    # Genesis & Channel
    genesis_block(opts, verbose=verbose)
    channel_tx(opts, verbose=verbose)
    # Setup node MSPs
    setup_nodes(opts, 'orderer', verbose=verbose)
    setup_nodes(opts, 'peer', verbose=verbose)


def runner_deploy(opts, upgrade=False, verbose=False):
    # Fabric
    runner_fabric(opts, upgrade=upgrade, verbose=verbose)
    # Composer
    runner_composer(opts, upgrade=upgrade, verbose=verbose)


def runner_fabric(opts, upgrade=False, verbose=False):
    # Setup CA
    runner_ca(opts, upgrade=upgrade, verbose=verbose)
    # Crypto material
    runner_crypto(opts, verbose=verbose)
    # Orderers
    runner_orderer(opts, upgrade=upgrade, verbose=verbose)
    # Peers
    runner_peer(opts, upgrade=upgrade, verbose=verbose)


def runner_orderer(opts,upgrade=False, verbose=False):
    setup_ord(opts, upgrade=upgrade, verbose=verbose)


def runner_peer(opts, upgrade=False, verbose=False):
    setup_peer(opts, upgrade=upgrade, verbose=verbose)
    setup_channel(opts, verbose=verbose)
