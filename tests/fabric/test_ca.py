from unittest.mock import call, patch, Mock

from kubernetes.client.rest import ApiException

from nephos.fabric.ca import ca_chart, ca_enroll, check_ca, setup_ca
from nephos.helpers.helm import HelmPreserve


class TestCaChart:
    OPTS = {
        "core": {"dir_values": "./some_dir", "chart_repo": "a_repo"},
        "cas": {"a-release": {"namespace": "ca-namespace"}},
    }

    @patch("nephos.fabric.ca.secret_read")
    @patch("nephos.fabric.ca.helm_upgrade")
    @patch("nephos.fabric.ca.helm_install")
    @patch("nephos.fabric.ca.helm_extra_vars")
    @patch("nephos.fabric.ca.helm_check")
    @patch("nephos.fabric.ca.get_version")
    def test_ca_chart(
        self,
        mock_get_version,
        mock_helm_check,
        mock_helm_extra_vars,
        mock_helm_install,
        mock_helm_upgrade,
        mock_secret_read,
    ):
        mock_secret_read.side_effect = [{"postgresql-password": "a_password"}]
        mock_get_version.side_effect = ["pg-version", "ca-version"]
        mock_helm_extra_vars.side_effect = ["extra-vars-pg", "extra-vars-ca"]
        ca_chart(self.OPTS, "a-release")
        mock_get_version.assert_has_calls(
            [call(self.OPTS, "postgresql"), call(self.OPTS, "hlf-ca")]
        )
        mock_helm_extra_vars.assert_has_calls(
            [
                call(
                    version="pg-version",
                    config_yaml="./some_dir/postgres-ca/a-release-pg.yaml",
                ),
                call(
                    version="ca-version",
                    config_yaml="./some_dir/hlf-ca/a-release.yaml",
                    env_vars=[("externalDatabase.password", "a_password")],
                ),
            ]
        )
        mock_helm_install.assert_has_calls(
            [
                call(
                    "stable",
                    "postgresql",
                    "a-release-pg",
                    "ca-namespace",
                    extra_vars="extra-vars-pg",
                ),
                call(
                    "a_repo",
                    "hlf-ca",
                    "a-release",
                    "ca-namespace",
                    extra_vars="extra-vars-ca",
                ),
            ]
        )
        mock_helm_upgrade.assert_not_called()
        mock_secret_read.assert_called_once_with(
            "a-release-pg-postgresql", "ca-namespace"
        )
        mock_helm_check.assert_has_calls(
            [
                call("postgresql", "a-release-pg", "ca-namespace"),
                call("hlf-ca", "a-release", "ca-namespace"),
            ]
        )

    @patch("nephos.fabric.ca.secret_read")
    @patch("nephos.fabric.ca.helm_upgrade")
    @patch("nephos.fabric.ca.helm_install")
    @patch("nephos.fabric.ca.helm_extra_vars")
    @patch("nephos.fabric.ca.helm_check")
    @patch("nephos.fabric.ca.get_version")
    def test_ca_chart_upgrade(
        self,
        mock_get_version,
        mock_helm_check,
        mock_helm_extra_vars,
        mock_helm_install,
        mock_helm_upgrade,
        mock_secret_read,
    ):
        mock_secret_read.side_effect = [{"postgresql-password": "a_password"}]
        mock_get_version.side_effect = ["ca-version"]
        mock_helm_extra_vars.side_effect = ["extra-vars-ca"]
        ca_chart(self.OPTS, "a-release", upgrade=True)
        mock_get_version.assert_has_calls([call(self.OPTS, "hlf-ca")])
        mock_helm_extra_vars.assert_called_once_with(
            version="ca-version",
            config_yaml="./some_dir/hlf-ca/a-release.yaml",
            env_vars=[("externalDatabase.password", "a_password")],
            preserve=(
                HelmPreserve(
                    "ca-namespace", "a-release-hlf-ca--ca", "CA_ADMIN", "adminUsername"
                ),
                HelmPreserve(
                    "ca-namespace",
                    "a-release-hlf-ca--ca",
                    "CA_PASSWORD",
                    "adminPassword",
                ),
            ),
        )
        mock_helm_install.assert_not_called()
        mock_helm_upgrade.assert_called_once_with(
            "a_repo", "hlf-ca", "a-release", extra_vars="extra-vars-ca"
        )
        mock_secret_read.assert_called_once_with(
            "a-release-pg-postgresql", "ca-namespace"
        )
        mock_helm_check.assert_has_calls([call("hlf-ca", "a-release", "ca-namespace")])


class TestCaEnroll:
    @patch("nephos.fabric.ca.sleep")
    def test_ca_enroll(self, mock_sleep):
        mock_pod_exec = Mock()
        mock_pod_exec.execute.side_effect = [
            (None, "error"),  # Get CA cert
            ("enrollment", None),
        ]
        mock_pod_exec.logs.side_effect = [
            "Not yet running",
            "Not yet running\nListening on localhost:7050",
        ]
        ca_enroll(mock_pod_exec)
        mock_pod_exec.execute.assert_has_calls(
            [
                call("cat /var/hyperledger/fabric-ca/msp/signcerts/cert.pem"),
                call(
                    "bash -c 'fabric-ca-client enroll -d -u http://$CA_ADMIN:$CA_PASSWORD@$SERVICE_DNS:7054'"
                ),
            ]
        )
        assert mock_pod_exec.logs.call_count == 2
        mock_sleep.assert_called_once_with(15)

    @patch("nephos.fabric.ca.sleep")
    def test_ca_enroll_serverfail(self, mock_sleep):
        mock_pod_exec = Mock()
        mock_pod_exec.execute.side_effect = [
            (None, "error"),  # Get CA cert
            (None, "error"),  # Enroll
            ("enrollment", None),
        ]
        mock_pod_exec.logs.side_effect = [
            "Not yet running\nListening on localhost:7050"
        ]
        ca_enroll(mock_pod_exec)
        mock_pod_exec.execute.assert_has_calls(
            [
                call("cat /var/hyperledger/fabric-ca/msp/signcerts/cert.pem"),
                call(
                    "bash -c 'fabric-ca-client enroll -d -u http://$CA_ADMIN:$CA_PASSWORD@$SERVICE_DNS:7054'"
                ),
                call(
                    "bash -c 'fabric-ca-client enroll -d -u http://$CA_ADMIN:$CA_PASSWORD@$SERVICE_DNS:7054'"
                ),
            ]
        )
        assert mock_pod_exec.logs.call_count == 1
        mock_sleep.assert_called_once_with(15)

    @patch("nephos.fabric.ca.sleep")
    def test_ca_enroll_again(self, mock_sleep):
        mock_pod_exec = Mock()
        mock_pod_exec.execute.side_effect = [("ca-cert", None)]  # Get CA cert
        mock_pod_exec.logs.side_effect = [
            "Not yet running\nListening on localhost:7050"
        ]
        ca_enroll(mock_pod_exec)
        mock_pod_exec.execute.assert_called_once_with(
            "cat /var/hyperledger/fabric-ca/msp/signcerts/cert.pem"
        )
        assert mock_pod_exec.logs.call_count == 1
        mock_sleep.assert_not_called()


class TestCheckCa:
    @patch("nephos.fabric.ca.execute_until_success")
    def test_check_ca(self, mock_execute_until_success):
        check_ca("an-ingress")
        mock_execute_until_success.assert_called_once_with(
            "curl https://an-ingress/cainfo"
        )

    @patch("nephos.fabric.ca.execute_until_success")
    def test_check_ca_cert(self, mock_execute_until_success):
        check_ca("an-ingress", cacert="./tls_cert.pem")
        mock_execute_until_success.assert_called_once_with(
            "curl https://an-ingress/cainfo --cacert ./tls_cert.pem"
        )


class TestSetupCa:
    OPTS = {
        "core": {"dir_config": "./a_dir"},
        "cas": {
            "root-ca": {"namespace": "root-namespace"},
            "int-ca": {"namespace": "int-namespace", "tls_cert": "./ca_cert.pem"},
        },
    }

    root_executer = Mock()
    root_executer.pod = "root-pod"
    int_executer = Mock()
    int_executer.pod = "int-pod"

    @patch("nephos.fabric.ca.ingress_read")
    @patch("nephos.fabric.ca.get_helm_pod")
    @patch("nephos.fabric.ca.check_ca")
    @patch("nephos.fabric.ca.ca_enroll")
    @patch("nephos.fabric.ca.ca_chart")
    def test_setup_ca(
        self,
        mock_ca_chart,
        mock_ca_enroll,
        mock_check_ca,
        mock_get_pod,
        mock_ingress_read,
    ):
        mock_get_pod.side_effect = [self.root_executer, self.int_executer]
        mock_ingress_read.side_effect = [ApiException, ["an-ingress"]]

        setup_ca(self.OPTS)
        mock_ca_chart.assert_has_calls(
            [
                call(opts=self.OPTS, release="root-ca", upgrade=False),
                call(opts=self.OPTS, release="int-ca", upgrade=False),
            ]
        )
        mock_get_pod.assert_has_calls(
            [
                call(namespace="root-namespace", release="root-ca", app="hlf-ca"),
                call(namespace="int-namespace", release="int-ca", app="hlf-ca"),
            ]
        )
        mock_ca_enroll.assert_has_calls(
            [call(self.root_executer), call(self.int_executer)]
        )
        mock_ingress_read.assert_has_calls(
            [
                call("root-ca-hlf-ca", namespace="root-namespace"),
                call("int-ca-hlf-ca", namespace="int-namespace"),
            ]
        )
        mock_check_ca.assert_called_once_with(
            ingress_host="an-ingress", cacert="./ca_cert.pem"
        )

    @patch("nephos.fabric.ca.ingress_read")
    @patch("nephos.fabric.ca.get_helm_pod")
    @patch("nephos.fabric.ca.check_ca")
    @patch("nephos.fabric.ca.ca_enroll")
    @patch("nephos.fabric.ca.ca_chart")
    def test_setup_ca_upgrade(
        self,
        mock_ca_chart,
        mock_ca_enroll,
        mock_check_ca,
        mock_get_pod,
        mock_ingress_read,
    ):
        mock_get_pod.side_effect = [self.root_executer, self.int_executer]
        mock_ingress_read.side_effect = [ApiException, ["an-ingress"]]
        setup_ca(self.OPTS, upgrade=True)
        mock_ca_chart.assert_has_calls(
            [
                call(opts=self.OPTS, release="root-ca", upgrade=True),
                call(opts=self.OPTS, release="int-ca", upgrade=True),
            ]
        )
        mock_get_pod.assert_has_calls(
            [
                call(namespace="root-namespace", release="root-ca", app="hlf-ca"),
                call(namespace="int-namespace", release="int-ca", app="hlf-ca"),
            ]
        )
        mock_ca_enroll.assert_has_calls(
            [call(self.root_executer), call(self.int_executer)]
        )
        mock_ingress_read.assert_has_calls(
            [
                call("root-ca-hlf-ca", namespace="root-namespace"),
                call("int-ca-hlf-ca", namespace="int-namespace"),
            ]
        )
        mock_check_ca.assert_called_once_with(
            ingress_host="an-ingress", cacert="./ca_cert.pem"
        )
