import os

from nephos.fabric.settings import load_config, check_cluster
from nephos.helpers.misc import execute
from nephos.runners import runner_fabric

CURRENT_PATH = os.path.abspath(os.path.split(__file__)[0])
# We will check cluster and flatly refuse to do integration testing unless on 'minikube'
CONTEXT = 'minikube'

# Get options
opts = load_config(os.path.join(CURRENT_PATH, '..', 'examples', 'dev', 'nephos_config.yaml'))

# TODO: There should be a more elegant way of obtaining all the releases
releases = (
    [key for key in opts['cas'].keys()] +
    opts['orderers']['names'] +
    [('cdb-' + key) for key in opts['peers']['names']] +
    [key for key in opts['peers']['names']]
)

# Run Fabric script
check_cluster(CONTEXT)  # Dangerous operation, recheck we have not shifted context
runner_fabric(opts, upgrade=False, verbose=False)

# Delete all deployments from Helm
check_cluster(CONTEXT)  # Dangerous operation, recheck we have not shifted context
execute('helm delete --purge {}'.format(' '.join(releases)))

# Delete the namespaces
check_cluster(CONTEXT)  # Dangerous operation, recheck we have not shifted context
execute('kubectl delete ns orderers peers'.format(' '.join(releases)))
