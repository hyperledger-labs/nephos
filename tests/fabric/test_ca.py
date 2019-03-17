from unittest.mock import call, patch, Mock

from kubernetes.client.rest import ApiException
from nephos.fabric.ca import ca_chart, ca_enroll, check_ca, setup_ca


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
    def test_ca_chart(self, mock_helm_check, mock_helm_extra_vars,
                      mock_helm_install, mock_helm_upgrade, mock_secret_read):
        mock_secret_read.side_effect = [{"postgresql-password": "a_password"}]
        env_vars = [("externalDatabase.password", "a_password")]
        ca_chart(self.OPTS, "a-release")
        mock_helm_install.assert_has_calls(
            [
                call(
                    "stable",
                    "postgresql",
                    "a-release-pg",
                    "ca-namespace",
                    config_yaml="./some_dir/postgres-ca/a-release-pg.yaml",
                    verbose=False,
                ),
                call(
                    "a_repo",
                    "hlf-ca",
                    "a-release",
                    "ca-namespace",
                    config_yaml="./some_dir/hlf-ca/a-release.yaml",
                    env_vars=env_vars,
                    verbose=False,
                ),
            ]
        )
        mock_helm_upgrade.assert_not_called()
        mock_secret_read.assert_called_once_with(
            "a-release-pg-postgresql", "ca-namespace", verbose=False
        )
        mock_helm_check.assert_has_calls([
            call("postgresql", "a-release-pg", "ca-namespace"),
            call("hlf-ca", "a-release", "ca-namespace"),
        ])

    @patch("nephos.fabric.ca.secret_read")
    @patch("nephos.fabric.ca.helm_upgrade")
    @patch("nephos.fabric.ca.helm_install")
    @patch("nephos.fabric.ca.helm_extra_vars")
    @patch("nephos.fabric.ca.helm_check")
    def test_ca_chart_upgrade(
        self, mock_helm_check, mock_helm_extra_vars,
            mock_helm_install, mock_helm_upgrade, mock_secret_read
    ):
        mock_secret_read.side_effect = [{"postgresql-password": "a_password"}]
        env_vars = [("externalDatabase.password", "a_password")]
        preserve = (
            ("ca-namespace", "a-release-hlf-ca", "CA_ADMIN", "adminUsername"),
            ("ca-namespace", "a-release-hlf-ca", "CA_PASSWORD", "adminPassword"),
        )
        ca_chart(self.OPTS, "a-release", upgrade=True)
        mock_helm_install.assert_called_once_with(
            "stable",
            "postgresql",
            "a-release-pg",
            "ca-namespace",
            config_yaml="./some_dir/postgres-ca/a-release-pg.yaml",
            verbose=False,
        )
        mock_helm_upgrade.assert_called_once_with(
            "a_repo",
            "hlf-ca",
            "a-release",
            "ca-namespace",
            config_yaml="./some_dir/hlf-ca/a-release.yaml",
            env_vars=env_vars,
            preserve=preserve,
            verbose=False,
        )
        mock_secret_read.assert_called_once_with(
            "a-release-pg-postgresql", "ca-namespace", verbose=False
        )
        mock_helm_check.assert_has_calls([
            call("postgresql", "a-release-pg", "ca-namespace"),
            call("hlf-ca", "a-release", "ca-namespace"),
        ])

    @patch("nephos.fabric.ca.secret_read")
    @patch("nephos.fabric.ca.helm_upgrade")
    @patch("nephos.fabric.ca.helm_install")
    @patch("nephos.fabric.ca.helm_extra_vars")
    @patch("nephos.fabric.ca.helm_check")
    def test_ca_chart_upgrade_old(
        self, mock_helm_check, mock_helm_extra_vars,
            mock_helm_install, mock_helm_upgrade, mock_secret_read
    ):
        mock_secret_read.side_effect = [{"postgresql-password": "a_password"}]
        mock_helm_upgrade.side_effect = [Exception, None]
        env_vars = [("externalDatabase.password", "a_password")]
        preserves = [
            (
                ("ca-namespace", "a-release-hlf-ca", "CA_ADMIN", "adminUsername"),
                ("ca-namespace", "a-release-hlf-ca", "CA_PASSWORD", "adminPassword"),
            ),
            (
                ("ca-namespace", "a-release-hlf-ca--ca", "CA_ADMIN", "adminUsername"),
                ("ca-namespace", "a-release-hlf-ca--ca", "CA_PASSWORD", "adminPassword"),
            ),
        ]
        ca_chart(self.OPTS, "a-release", upgrade=True)
        mock_helm_install.assert_called_once_with(
            "stable",
            "postgresql",
            "a-release-pg",
            "ca-namespace",
            config_yaml="./some_dir/postgres-ca/a-release-pg.yaml",
            verbose=False,
        )
        mock_helm_upgrade.assert_has_calls(
            [
                call(
                    "a_repo",
                    "hlf-ca",
                    "a-release",
                    "ca-namespace",
                    config_yaml="./some_dir/hlf-ca/a-release.yaml",
                    env_vars=env_vars,
                    preserve=preserves[0],
                    verbose=False,
                ),
                call(
                    "a_repo",
                    "hlf-ca",
                    "a-release",
                    "ca-namespace",
                    config_yaml="./some_dir/hlf-ca/a-release.yaml",
                    env_vars=env_vars,
                    preserve=preserves[1],
                    verbose=False,
                ),
            ]
        )
        mock_secret_read.assert_called_once_with(
            "a-release-pg-postgresql", "ca-namespace", verbose=False
        )
        mock_helm_check.assert_has_calls([
            call("postgresql", "a-release-pg", "ca-namespace"),
            call("hlf-ca", "a-release", "ca-namespace"),
        ])

    @patch("nephos.fabric.ca.secret_read")
    @patch("nephos.fabric.ca.helm_upgrade")
    @patch("nephos.fabric.ca.helm_install")
    @patch("nephos.fabric.ca.helm_extra_vars")
    @patch("nephos.fabric.ca.helm_check")
    def test_ca_chart_verbose(
        self, mock_helm_check, mock_helm_extra_vars,
            mock_helm_install, mock_helm_upgrade, mock_secret_read
    ):
        mock_secret_read.side_effect = [{"postgresql-password": "a_password"}]
        env_vars = [("externalDatabase.password", "a_password")]
        ca_chart(self.OPTS, "a-release", verbose=True)
        mock_helm_install.assert_has_calls(
            [
                call(
                    "stable",
                    "postgresql",
                    "a-release-pg",
                    "ca-namespace",
                    config_yaml="./some_dir/postgres-ca/a-release-pg.yaml",
                    verbose=True,
                ),
                call(
                    "a_repo",
                    "hlf-ca",
                    "a-release",
                    "ca-namespace",
                    config_yaml="./some_dir/hlf-ca/a-release.yaml",
                    env_vars=env_vars,
                    verbose=True,
                ),
            ]
        )
        mock_helm_upgrade.assert_not_called()
        mock_secret_read.assert_called_once_with(
            "a-release-pg-postgresql", "ca-namespace", verbose=True
        )
        mock_helm_check.assert_has_calls([
            call("postgresql", "a-release-pg", "ca-namespace"),
            call("hlf-ca", "a-release", "ca-namespace"),
        ])


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
        check_ca("an-ingress", verbose=False)
        mock_execute_until_success.assert_called_once_with(
            "curl https://an-ingress/cainfo", verbose=False
        )

    @patch("nephos.fabric.ca.execute_until_success")
    def test_check_ca_cert(self, mock_execute_until_success):
        check_ca("an-ingress", cacert="./tls_cert.pem", verbose=True)
        mock_execute_until_success.assert_called_once_with(
            "curl https://an-ingress/cainfo --cacert ./tls_cert.pem", verbose=True
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
    @patch("nephos.fabric.ca.get_pod")
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
                call(opts=self.OPTS, release="root-ca", upgrade=False, verbose=False),
                call(opts=self.OPTS, release="int-ca", upgrade=False, verbose=False),
            ]
        )
        mock_get_pod.assert_has_calls(
            [
                call(
                    namespace="root-namespace",
                    release="root-ca",
                    app="hlf-ca",
                    verbose=False,
                ),
                call(
                    namespace="int-namespace",
                    release="int-ca",
                    app="hlf-ca",
                    verbose=False,
                ),
            ]
        )
        mock_ca_enroll.assert_has_calls(
            [call(self.root_executer), call(self.int_executer)]
        )
        mock_ingress_read.assert_has_calls(
            [
                call("root-ca-hlf-ca", namespace="root-namespace", verbose=False),
                call("int-ca-hlf-ca", namespace="int-namespace", verbose=False),
            ]
        )
        mock_check_ca.assert_called_once_with(
            ingress_host="an-ingress", cacert="./ca_cert.pem", verbose=False
        )

    @patch("nephos.fabric.ca.ingress_read")
    @patch("nephos.fabric.ca.get_pod")
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
        setup_ca(self.OPTS, upgrade=True, verbose=True)
        mock_ca_chart.assert_has_calls(
            [
                call(opts=self.OPTS, release="root-ca", upgrade=True, verbose=True),
                call(opts=self.OPTS, release="int-ca", upgrade=True, verbose=True),
            ]
        )
        mock_get_pod.assert_has_calls(
            [
                call(
                    namespace="root-namespace",
                    release="root-ca",
                    app="hlf-ca",
                    verbose=True,
                ),
                call(
                    namespace="int-namespace",
                    release="int-ca",
                    app="hlf-ca",
                    verbose=True,
                ),
            ]
        )
        mock_ca_enroll.assert_has_calls(
            [call(self.root_executer), call(self.int_executer)]
        )
        mock_ingress_read.assert_has_calls(
            [
                call("root-ca-hlf-ca", namespace="root-namespace", verbose=True),
                call("int-ca-hlf-ca", namespace="int-namespace", verbose=True),
            ]
        )
        mock_check_ca.assert_called_once_with(
            ingress_host="an-ingress", cacert="./ca_cert.pem", verbose=True
        )
