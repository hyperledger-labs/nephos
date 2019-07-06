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

from collections import OrderedDict
from os import path

import yaml

from nephos.helpers.k8s import context_get
from nephos.fabric.utils import get_msps


# YAML module will load data using an OrderedDict
def dict_constructor(loader, node):
    return OrderedDict(loader.construct_pairs(node))


def dict_representer(dumper, data):
    return dumper.represent_dict(data.items())


yaml.add_representer(OrderedDict, dict_representer)
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, dict_constructor)


def check_cluster(cluster_name):
    """Check that we are using the correct K8S cluster.

    Args:
        cluster_name (str): Name of K8S cluster.
    """
    context = context_get()
    if context["context"]["cluster"] != cluster_name:
        message = f"We expect to use cluster {cluster_name}, but are instead using cluster {context['context']['cluster']}",
        raise ValueError(message)


def get_namespace(opts, msp=None, ca=None):
    """Get relevant namespace where MSP or CA should be located.

    Args:
        opts (dict): Nephos options dict.
        msp (str): Name of Membership Service Provider (MSP).
        ca (str): Name of Certificate Authority (CA).

    Returns:
        str: Namespace relating to either an MSP or a CA.
    """
    if msp is not None:
        if msp in list(get_msps(opts=opts)):
            if "namespace" in opts["msps"][msp]:
                # Specific MSP-based namespace
                return opts["msps"][msp]["namespace"]
        else:
            raise KeyError(f'Settings dict does not contain MSP "{msp}"')
    elif ca is not None:
        if "cas" in opts and ca in opts["cas"]:
            ca_values = opts["cas"][ca]
        else:
            raise KeyError(f'Settings dict does not contain CA "{ca}"')
        if "namespace" in ca_values:
            # Specific MSP-based namespace
            return ca_values["namespace"]
    # Default case is to return core namespace
    return opts["core"]["namespace"]


def get_version(opts, app):
    """Get version of a specific app

    Args:
        opts (dict): Nephos options dict.
        app (str): Helm application name.

    Returns:
        str: Desired version of Helm app, if specified. Defaults to None.
    """
    if "versions" in opts and app in opts["versions"]:
        return opts["versions"][app]
    else:
        return None


def load_config(settings_file):
    """Load configuration from Nephos options/settings YAML file.

    Args:
        settings_file (str): Name of YAML file containing Nephos options/settings.

    Returns:
        dict: Nephos options/settings.
    """
    with open(settings_file) as f:
        data = yaml.safe_load(f)
    if "cluster" in data["core"]:
        check_cluster(data["core"]["cluster"])
    if path.isdir(data["core"]["chart_repo"]):
        # TODO: This abspath/expanduser combo can be refactored to another function
        data["core"]["chart_repo"] = path.abspath(
            path.expanduser(data["core"]["chart_repo"])
        )
    data["core"]["dir_config"] = path.abspath(
        path.expanduser(data["core"]["dir_config"])
    )
    data["core"]["dir_crypto"] = path.abspath(
        path.expanduser(data["core"]["dir_crypto"])
    )
    data["core"]["dir_values"] = path.abspath(
        path.expanduser(data["core"]["dir_values"])
    )
    return data
