#! /usr/bin/env python
from __future__ import print_function

import json

import click
from blessings import Terminal

from nephos.runners import (runner_ca, runner_composer, runner_crypto,
                            runner_deploy, runner_fabric, runner_orderer, runner_peer)

from nephos.fabric.settings import load_config


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
def ca(ctx):
    opts = load_config(ctx.obj['settings_file'])
    runner_ca(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install Hyperledger  Composer'))
@click.pass_context
def composer(ctx):
    opts = load_config(ctx.obj['settings_file'])
    runner_composer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Obtain cryptographic materials from CAs'))
@click.pass_context
def crypto(ctx):
    opts = load_config(ctx.obj['settings_file'])
    # Set up Admin MSPs
    runner_crypto(opts, verbose=ctx.obj['verbose'])


# TODO: Can we compose several CLI commands here to avoid copied code?
@cli.command(help=TERM.cyan('Install end-to-end Fabric/Composer network'))
@click.pass_context
def deploy(ctx):
    opts = load_config(ctx.obj['settings_file'])
    # Setup CA
    runner_deploy(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install end-to-end Hyperledger Fabric network'))
@click.pass_context
def fabric(ctx):
    opts = load_config(ctx.obj['settings_file'])
    # Setup CA
    runner_fabric(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install Hyperledger Fabric Orderers'))
@click.pass_context
def orderer(ctx):
    opts = load_config(ctx.obj['settings_file'])
    runner_orderer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Install Hyperledger Fabric Peers'))
@click.pass_context
def peer(ctx):
    opts = load_config(ctx.obj['settings_file'])
    runner_peer(opts, upgrade=ctx.obj['upgrade'], verbose=ctx.obj['verbose'])


@cli.command(help=TERM.cyan('Load "nephos" settings YAML file'))
@click.pass_context
def settings(ctx):
    data = load_config(ctx.obj['settings_file'])
    print('Settings successfully loaded...\n')
    if ctx.obj['verbose']:
        # TODO: Pretty print & colorise output
        print(json.dumps(data, indent=4))


if __name__ == "__main__":
    cli(obj={})
