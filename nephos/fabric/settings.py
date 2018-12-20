from collections import OrderedDict
from os import path

import yaml

from nephos.helpers.k8s import context_get


# YAML module will load data using an OrderedDict
def dict_representer(dumper, data):
    return dumper.represent_dict(data.iteritems())


def dict_constructor(loader, node):
    return OrderedDict(loader.construct_pairs(node))


yaml.add_representer(OrderedDict, dict_representer)
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, dict_constructor)


def check_cluster(cluster_name):
    context = context_get()
    if context['context']['cluster'] != cluster_name:
        message = 'We expect to use cluster {}, but are instead using cluster {}'.format(
            cluster_name, context['context']['cluster'])
        raise ValueError(message)


def load_config(settings_file):
    with open(settings_file) as f:
        data = yaml.load(f)
    if 'cluster' in data['core']:
        check_cluster(data['core']['cluster'])
    if path.isdir(data['core']['chart_repo']):
        # TODO: This abspath/expanduser combo can be refactored to another function
        data['core']['chart_repo'] = path.abspath(path.expanduser(data['core']['chart_repo']))
    data['core']['dir_config'] = path.abspath(path.expanduser(data['core']['dir_config']))
    data['core']['dir_values'] = path.abspath(path.expanduser(data['core']['dir_values']))
    return data
