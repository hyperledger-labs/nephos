from nephos.fabric.ca import setup_ca
from nephos.fabric.crypto import admin_msp, genesis_block, channel_tx, setup_nodes
from nephos.fabric.ord import setup_ord
from nephos.fabric.peer import setup_peer, setup_channel
from nephos.composer.install import deploy_composer, install_network, setup_admin
from nephos.composer.upgrade import upgrade_network


def runner_ca(opts, upgrade=False, verbose=False):
    if opts["cas"]:
        setup_ca(opts, upgrade=upgrade, verbose=verbose)
    else:
        print("No CAs defined in Nephos settings, ignoring CA setup")


def runner_composer(opts, upgrade=False, verbose=False):
    deploy_composer(opts, upgrade=upgrade, verbose=verbose)
    setup_admin(opts, verbose=verbose)
    install_network(opts, verbose=verbose)


def runner_composer_up(opts, verbose=False):
    upgrade_network(opts, verbose=verbose)


def runner_crypto(opts, verbose=False):
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


def runner_orderer(opts, upgrade=False, verbose=False):
    setup_ord(opts, upgrade=upgrade, verbose=verbose)


def runner_peer(opts, upgrade=False, verbose=False):
    setup_peer(opts, upgrade=upgrade, verbose=verbose)
    setup_channel(opts, verbose=verbose)
