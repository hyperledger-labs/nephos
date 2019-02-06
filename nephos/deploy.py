#! /usr/bin/env python

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

import json

import click
from blessings import Terminal

from nephos.runners import (
    runner_ca,
    runner_composer,
    runner_composer_up,
    runner_crypto,
    runner_deploy,
    runner_fabric,
    runner_orderer,
    runner_peer,
)

from nephos.fabric.settings import load_config


TERM = Terminal()


class Settings(object):
    def __init__(self, settings_file, upgrade, verbose):
        self.settings_file = settings_file
        self.upgrade = upgrade
        self.verbose = verbose


pass_settings = click.make_pass_decorator(Settings, ensure=True)


@click.group(
    help=TERM.green("Nephos helps you install Hyperledger Fabric on Kubernetes")
)
@click.option(
    "--settings_file",
    "-f",
    required=True,
    help=TERM.cyan("YAML file containing HLF options"),
)
@click.option(
    "--upgrade",
    "-u",
    is_flag=True,
    default=False,
    help=TERM.cyan("Do we wish to upgrade already installed components?"),
)
@click.option(
    "--verbose/--quiet",
    "-v/-q",
    default=False,
    help=TERM.cyan("Do we want verbose output?"),
)
@click.pass_context
def cli(ctx, settings_file, upgrade, verbose):
    ctx.obj = Settings(settings_file, upgrade, verbose)


@cli.command(help=TERM.cyan("Install Hyperledger Fabric Certificate Authorities"))
@pass_settings
def ca(settings):
    opts = load_config(settings.settings_file)
    runner_ca(opts, upgrade=settings.upgrade, verbose=settings.verbose)


@cli.command(help=TERM.cyan("Install Hyperledger Composer"))
@pass_settings
def composer(settings):
    opts = load_config(settings.settings_file)
    runner_composer(opts, upgrade=settings.upgrade, verbose=settings.verbose)


@cli.command(help=TERM.cyan("Upgrade Hyperledger Composer"))
@pass_settings
def composer_up(settings):
    opts = load_config(settings.settings_file)
    runner_composer_up(opts, verbose=settings.verbose)


@cli.command(help=TERM.cyan("Obtain cryptographic materials from CAs"))
@pass_settings
def crypto(settings):
    opts = load_config(settings.settings_file)
    runner_crypto(opts, verbose=settings.verbose)


# TODO: Can we compose several CLI commands here to avoid copied code?
@cli.command(help=TERM.cyan("Install end-to-end Fabric/Composer network"))
@pass_settings
def deploy(settings):
    opts = load_config(settings.settings_file)
    runner_deploy(opts, upgrade=settings.upgrade, verbose=settings.verbose)


@cli.command(help=TERM.cyan("Install end-to-end Hyperledger Fabric network"))
@pass_settings
def fabric(settings):
    opts = load_config(settings.settings_file)
    runner_fabric(opts, upgrade=settings.upgrade, verbose=settings.verbose)


@cli.command(help=TERM.cyan("Install Hyperledger Fabric Orderers"))
@pass_settings
def orderer(settings):
    opts = load_config(settings.settings_file)
    runner_orderer(opts, upgrade=settings.upgrade, verbose=settings.verbose)


@cli.command(help=TERM.cyan("Install Hyperledger Fabric Peers"))
@pass_settings
def peer(settings):
    opts = load_config(settings.settings_file)
    runner_peer(opts, upgrade=settings.upgrade, verbose=settings.verbose)


@cli.command(help=TERM.cyan('Load "nephos" settings YAML file'))
@pass_settings
def settings(settings):
    data = load_config(settings.settings_file)
    print("Settings successfully loaded...\n")
    if settings.verbose:
        # TODO: Pretty print & colorise output
        print(json.dumps(data, indent=4))


if __name__ == "__main__":  # pragma: no cover
    cli(obj={})
