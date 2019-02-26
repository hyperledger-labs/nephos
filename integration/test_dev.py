import os

from click.testing import CliRunner

from nephos.deploy import cli

RUNNER = CliRunner()

from nephos.fabric.settings import load_config, check_cluster
from nephos.helpers.misc import execute

CURRENT_PATH = os.path.abspath(os.path.split(__file__)[0])


class TestIntegrationDev:
    # We will check cluster and flatly refuse to do integration testing unless on 'minikube'
    CONTEXT = 'minikube'
    CONFIG = os.path.join(CURRENT_PATH, '..', 'examples', 'dev', 'nephos_config.yaml')

    def test_integration_dev(self):
        # Get options
        opts = load_config(self.CONFIG)

        # TODO: There should be a more elegant way of obtaining all the releases
        releases = (
            [key for key in opts['cas'].keys()] +
            [key + '-pg' for key in opts['cas'].keys()] +
            opts['orderers']['names'] +
            [('cdb-' + key) for key in opts['peers']['names']] +
            [key for key in opts['peers']['names']]
        )

        # Run Fabric script
        check_cluster(self.CONTEXT)  # Dangerous operation, recheck we have not shifted context
        result = RUNNER.invoke(cli, ["--settings_file", self.CONFIG, "fabric"])

        # Delete all deployments from Helm
        check_cluster(self.CONTEXT)  # Dangerous operation, recheck we have not shifted context
        execute('helm delete --purge {}'.format(' '.join(releases)))

        # Delete the namespaces
        check_cluster(self.CONTEXT)  # Dangerous operation, recheck we have not shifted context
        execute('kubectl delete ns orderers peers'.format(' '.join(releases)))

        # Finally assert everything ran correctly
        assert result.exit_code == 0
