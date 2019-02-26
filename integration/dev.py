import os

from nephos.fabric.settings import load_config
from nephos.runners import runner_fabric

CURRENT_PATH = os.path.abspath(os.path.split(__file__)[0])


opts = load_config(os.path.join(CURRENT_PATH, '..', 'examples', 'dev', 'nephos_config.yaml'))
runner_fabric(opts, upgrade=False, verbose=False)
