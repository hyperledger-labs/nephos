import os

from nephos.fabric.settings import load_config, check_cluster
from nephos.helpers.k8s import ns_create
from nephos.helpers.misc import execute
from nephos.runners import runner_fabric

CURRENT_PATH = os.path.abspath(os.path.split(__file__)[0])


class TestIntegrationQa:
    # We will check cluster and flatly refuse to do integration testing unless on 'minikube'
    CONTEXT = "minikube"
    CONFIG = os.path.join(CURRENT_PATH, "..", "examples", "qa", "nephos_config.yaml")
    TLS_PATH = os.path.join(CURRENT_PATH, "..", "examples", "ca-nephos-local")

    def test_integration_qa(self):
        # Get options
        opts = load_config(self.CONFIG)

        # Save TLS of each CA in its relevant secret
        ns_create("cas")

        # TODO: Eventually we should enable getting path for multiple CAs programatically
        execute(
            (
                "kubectl -n cas create secret tls ca--tls "
                + f"--cert={self.TLS_PATH}.crt "
                + f"--key={self.TLS_PATH}.key"
            )
        )

        # TODO: There should be a more elegant way of obtaining all the releases
        releases = (
            [key for key in opts["cas"].keys()]
            + [key + "-pg" for key in opts["cas"].keys()]
            + list(opts["msps"]["AlphaMSP"]["orderers"]["nodes"].keys())
            + [
                ("cdb-" + key)
                for key in opts["msps"]["BetaMSP"]["peers"]["nodes"].keys()
            ]
            + [key for key in opts["msps"]["BetaMSP"]["peers"]["nodes"].keys()]
        )

        # Run Fabric script
        check_cluster(
            self.CONTEXT
        )  # Dangerous operation, recheck we have not shifted context
        runner_fabric(opts)

        # Delete all deployments from Helm
        check_cluster(
            self.CONTEXT
        )  # Dangerous operation, recheck we have not shifted context
        execute(f"helm delete --purge {' '.join(releases)}")

        # Delete the namespaces
        check_cluster(
            self.CONTEXT
        )  # Dangerous operation, recheck we have not shifted context
        execute("kubectl delete ns cas alpha beta")
