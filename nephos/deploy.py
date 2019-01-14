#! /usr/bin/env python
from __future__ import print_function

import json

import click
from blessings import Terminal

from nephos.helpers.k8s import ns_create
from nephos.fabric.settings import load_config
from nephos.fabric.ca import setup_ca
from nephos.fabric.crypto import setup_blocks, setup_nodes
from nephos.fabric.ord import setup_ord
from nephos.fabric.peer import setup_peer, setup_channel
from nephos.composer.install import deploy_composer, install_network, setup_admin


TERM = Terminal()


@click.group(help=TERM.green('Nephos helps you install Hyperledger Fabric on Kubernetes'))
@click.option('--settings_file', '-f', required=True,
              help=TERM.cyan('YAML file containing HLF options'))
@click.option('--upgrade', '-u', is_flag=True, default=False,
              help=TERM.cyan('Do we wish to upgrade already installed components?'))
@click.option('--verbose/--quiet', '-v/-q', default=False,
              help=TERM.cyan('Do we want verbose output?'))
@click.pass_context
def cli(ctx, settings_file, upgrade, verbose):
    ctx.obj['settings_file'] = settings_file
    ctx.obj['upgrade'] = upgrade
    ctx.obj['verbose'] = verbose


@cli.command(help=TERM.cyan('Install Hyperledger Fabric Certificate Authorities'))
@click.pass_context
def ca(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_ca(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install Hyperledger  Composer'))
@click.pass_context
def composer(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    deploy_composer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_admin(opts, verbose=ctx.obj['verbose'])
    install_network(opts, verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Obtain cryptographic materials from CAs'))
@click.pass_context
def crypto(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_blocks(opts, verbose=ctx.obj['verbose'])
    setup_nodes(opts, 'orderer', verbose=ctx.obj['verbose'])
    setup_nodes(opts, 'peer', verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install end-to-end Fabric/Composer network'))
@click.pass_context
def deploy(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_ca(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    # Crypto material
    setup_blocks(opts, verbose=ctx.obj['verbose'])
    setup_nodes(opts, 'orderer', verbose=ctx.obj['verbose'])
    setup_nodes(opts, 'peer', verbose=ctx.obj['verbose'])
    # Orderers
    setup_ord(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_peer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_channel(opts, verbose=ctx.obj['verbose'])
    # Composer
    deploy_composer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_admin(opts, verbose=ctx.obj['verbose'])
    install_network(opts, verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install end-to-end Hyperledger Fabric network'))
@click.pass_context
def fabric(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_ca(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_blocks(opts, verbose=ctx.obj['verbose'])
    setup_nodes(opts, 'orderer', verbose=ctx.obj['verbose'])
    setup_nodes(opts, 'peer', verbose=ctx.obj['verbose'])
    setup_ord(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_peer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_channel(opts, verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install Hyperledger Fabric Orderers'))
@click.pass_context
def orderer(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_ord(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install Hyperledger Fabric Peers'))
@click.pass_context
def peer(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_peer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_channel(opts, verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Load "nephos" settings YAML file'))
@click.pass_context
def settings(ctx):  # pragma: no cover
    data = load_config(ctx.obj['settings_file'])
    print('Settings successfully loaded...\n')
    if ctx.obj['verbose']:
        # TODO: Pretty print & colorise output
        print(json.dumps(data, indent=4))


if __name__ == "__main__":  # pragma: no cover
    cli(obj={})
