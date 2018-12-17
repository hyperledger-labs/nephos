#! /usr/bin/env python
from __future__ import print_function

import json

import click
from blessings import Terminal

from hlf.helpers.k8s import ns_create
from hlf.fabric.settings import load_config
from hlf.fabric.ca import setup_ca
from hlf.fabric.crypto import setup_blocks, setup_nodes
from hlf.fabric.ord import setup_ord
from hlf.fabric.peer import setup_peer, setup_channel
from hlf.composer.setup import deploy_composer, install_network, setup_admin


TERM = Terminal()


@click.group()
@click.option('--settings_file', '-f', required=True, help='YAML file containing HLF options')
@click.option('--upgrade', '-u', is_flag=True, default=False)
@click.option('--verbose/--quiet', '-v/-q', default=False)
@click.pass_context
def cli(ctx, settings_file, upgrade, verbose):
    ctx.obj['settings_file'] = settings_file
    ctx.obj['upgrade'] = upgrade
    ctx.obj['verbose'] = verbose


@cli.command()
@click.pass_context
def ca(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_ca(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])



@cli.command()
@click.pass_context
def composer(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    deploy_composer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_admin(opts, verbose=ctx.obj['verbose'])
    install_network(opts, verbose=ctx.obj['verbose'])


@click.command()
@click.pass_context
def crypto(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_blocks(opts, verbose=ctx.obj['verbose'])
    setup_nodes(opts, 'orderer', verbose=ctx.obj['verbose'])
    setup_nodes(opts, 'peer', verbose=ctx.obj['verbose'])


@cli.command()
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



@cli.command()
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


@cli.command()
@click.pass_context
def orderer(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_ord(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command()
@click.pass_context
def peer(ctx):  # pragma: no cover
    opts = load_config(ctx.obj['settings_file'])
    ns_create(opts['core']['namespace'], verbose=ctx.obj['verbose'])
    setup_peer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])
    setup_channel(opts, verbose=ctx.obj['verbose'])


@cli.command()
@click.pass_context
def settings(ctx):  # pragma: no cover
    data = load_config(ctx.obj['settings_file'])
    print('Settings successfully loaded...\n')
    if ctx.obj['verbose']:
        # TODO: Pretty print & colorise output
        print(json.dumps(data, indent=4))


if __name__ == "__main__":  # pragma: no cover
    cli(obj={})
