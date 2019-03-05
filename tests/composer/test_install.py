from unittest.mock import call, patch, Mock

from kubernetes.client.rest import ApiException
import pytest

from nephos.helpers.helm import HelmPreserve
from nephos.composer.install import (
    get_composer_data,
    composer_connection,
    deploy_composer,
    setup_admin,
    install_network,
)


class TestGetComposerData:
    OPTS = {
        "composer": {"name": "hlc"},
        "msps": {"peer_MSP": {"namespace": "peer-namespace"}},
        "peers": {"msp": "peer_MSP"},
    }

    @patch("nephos.composer.install.get_app_info")
    def test_get_composer_data(self, mock_get_app_info):
        mock_get_app_info.side_effect = [{"api-key": "hlc-key", "url": "an-ingress"}]
        get_composer_data(self.OPTS)
        mock_get_app_info.assert_called_once_with(
            "peer-namespace",
            "hlc-hl-composer-rest",
            "hlc-hl-composer-rest",
            secret_key="COMPOSER_APIKEY",
            verbose=False,
        )

    @patch("nephos.composer.install.get_app_info")
    def test_get_composer_data_exception(self, mock_get_app_info):
        mock_get_app_info.side_effect = [ValueError]
        with pytest.raises(ValueError):
            get_composer_data(self.OPTS, verbose=True)
        mock_get_app_info.assert_called_once_with(
            "peer-namespace",
            "hlc-hl-composer-rest",
            "hlc-hl-composer-rest",
            secret_key="COMPOSER_APIKEY",
            verbose=True,
        )


class TestComposerConnection:
    OPTS = {
        "cas": {"peer-ca": {"msp": "peer-msp", "namespace": "ca-namespace"}},
        "composer": {"name": "hlc", "secret_connection": "connection-secret"},
        "msps": {
            "ord_MSP": {"namespace": "ord-namespace"},
            "peer_MSP": {"namespace": "peer-namespace", "ca": "peer-ca"},
        },
        "orderers": {"msp": "ord_MSP"},
        "peers": {"channel_name": "a-channel", "msp": "peer_MSP"},
    }

    @patch("nephos.composer.install.json_ct")
    @patch("nephos.composer.install.ingress_read")
    @patch("nephos.composer.install.cm_read")
    @patch("nephos.composer.install.cm_create")
    def test_composer_connection(
        self, mock_cm_create, mock_cm_read, mock_ingress_read, mock_json_ct
    ):
        mock_cm_read.side_effect = [ApiException]
        mock_json_ct.side_effect = ["cm-data"]
        composer_connection(self.OPTS)
        mock_ingress_read.assert_called_once_with(
            "peer-ca-hlf-ca", namespace="ca-namespace", verbose=False
        )
        mock_cm_read.assert_called_once_with(
            "connection-secret", "peer-namespace", verbose=False
        )
        mock_json_ct.assert_called_once()
        mock_cm_create.assert_called_once_with(
            {"connection.json": "cm-data"},
            "connection-secret",
            "peer-namespace",
            verbose=False,
        )

    @patch("nephos.composer.install.json_ct")
    @patch("nephos.composer.install.ingress_read")
    @patch("nephos.composer.install.cm_read")
    @patch("nephos.composer.install.cm_create")
    def test_composer_connection_again(
        self, mock_cm_create, mock_cm_read, mock_ingress_read, mock_json_ct
    ):
        mock_cm_read.side_effect = [{"connection.json": "cm-data"}]
        composer_connection(self.OPTS, verbose=True)
        mock_ingress_read.assert_called_once_with(
            "peer-ca-hlf-ca", namespace="ca-namespace", verbose=True
        )
        mock_cm_read.assert_called_once_with(
            "connection-secret", "peer-namespace", verbose=True
        )
        mock_json_ct.assert_not_called()
        mock_cm_create.assert_not_called()


class TestDeployComposer:
    OPTS = {
        "composer": {"name": "hlc", "secret_bna": "bna-secret"},
        "core": {"chart_repo": "a-repo", "dir_values": "./a_dir"},
        "msps": {"peer_MSP": {"namespace": "peer-namespace"}},
        "peers": {"msp": "peer_MSP"},
    }

    @patch("nephos.composer.install.secret_from_file")
    @patch("nephos.composer.install.helm_upgrade")
    @patch("nephos.composer.install.helm_install")
    @patch("nephos.composer.install.composer_connection")
    def test_deploy_composer(
        self,
        mock_composer_connection,
        mock_helm_install,
        mock_helm_upgrade,
        mock_secret_from_file,
    ):
        deploy_composer(self.OPTS)
        mock_secret_from_file.assert_called_once_with(
            secret="bna-secret", namespace="peer-namespace", verbose=False
        )
        mock_composer_connection.assert_called_once_with(self.OPTS, verbose=False)
        mock_helm_install.assert_called_once_with(
            "a-repo",
            "hl-composer",
            "hlc",
            "peer-namespace",
            pod_num=3,
            config_yaml="./a_dir/hl-composer/hlc.yaml",
            verbose=False,
        )
        mock_helm_upgrade.assert_not_called()

    @patch("nephos.composer.install.secret_from_file")
    @patch("nephos.composer.install.helm_upgrade")
    @patch("nephos.composer.install.helm_install")
    @patch("nephos.composer.install.composer_connection")
    def test_deploy_composer_upgrade(
        self,
        mock_composer_connection,
        mock_helm_install,
        mock_helm_upgrade,
        mock_secret_from_file,
    ):
        deploy_composer(self.OPTS, upgrade=True, verbose=True)
        mock_secret_from_file.assert_called_once_with(
            secret="bna-secret", namespace="peer-namespace", verbose=True
        )
        mock_composer_connection.assert_called_once_with(self.OPTS, verbose=True)
        mock_helm_install.assert_not_called()
        mock_helm_upgrade.assert_called_once_with(
            "a-repo",
            "hl-composer",
            "hlc",
            "peer-namespace",
            pod_num=3,
            config_yaml="./a_dir/hl-composer/hlc.yaml",
            preserve=(
                HelmPreserve(
                    "hlc-hl-composer-rest", "COMPOSER_APIKEY", "rest.config.apiKey"
                ),
            ),
            verbose=True,
        )


class TestSetupAdmin:
    OPTS = {
        "cas": {"peer-ca": {"org_admin": "an-admin", "org_adminpw": "a-password"}},
        "composer": {"name": "hlc"},
        "msps": {"peer_MSP": {"namespace": "peer-namespace"}},
        "peers": {"msp": "peer_MSP"},
    }

    @patch("nephos.composer.install.get_pod")
    def test_setup_admin(self, mock_get_pod):
        mock_pod = Mock()
        mock_pod.execute.side_effect = [
            (None, "error"),  # composer card list admin
            ("Create card", None),  # composer card create
            ("Import card", None),  # composer card import admin
            ("a-network_a-version.bna", None),  # ls BNA
        ]
        mock_get_pod.side_effect = [mock_pod]
        setup_admin(self.OPTS)
        mock_get_pod.assert_called_once_with(
            "peer-namespace", "hlc", "hl-composer", verbose=False
        )
        mock_pod.execute.assert_has_calls(
            [
                call("composer card list --card PeerAdmin@hlfv1"),
                call(
                    "composer card create "
                    + "-p /hl_config/hlc-connection/connection.json "
                    + "-u PeerAdmin -c /hl_config/admin/signcerts/cert.pem "
                    + "-k /hl_config/admin/keystore/key.pem "
                    + " -r PeerAdmin -r ChannelAdmin "
                    + "--file /home/composer/PeerAdmin@hlfv1"
                ),
                call(
                    "composer card import "
                    + "--file /home/composer/PeerAdmin@hlfv1.card"
                ),
            ]
        )

    @patch("nephos.composer.install.get_pod")
    def test_setup_admin_again(self, mock_get_pod):
        mock_pod = Mock()
        mock_pod.execute.side_effect = [
            ("an-admin.card", None)  # composer card list admin
        ]
        mock_get_pod.side_effect = [mock_pod]
        setup_admin(self.OPTS, verbose=True)
        mock_get_pod.assert_called_once_with(
            "peer-namespace", "hlc", "hl-composer", verbose=True
        )
        mock_pod.execute.assert_has_calls(
            [call("composer card list --card PeerAdmin@hlfv1")]
        )


class TestInstallNetwork:
    OPTS = {
        "cas": {"peer-ca": {}},
        "composer": {"name": "hlc"},
        "msps": {
            "peer_MSP": {
                "ca": "peer-ca",
                "namespace": "peer-namespace",
                "org_admin": "an-admin",
                "org_adminpw": "a-password",
            }
        },
        "peers": {"msp": "peer_MSP"},
    }

    @patch("nephos.composer.install.get_pod")
    @patch("nephos.composer.install.admin_creds")
    def test_install_network(self, mock_admin_creds, mock_get_pod):
        mock_pod = Mock()
        mock_pod.execute.side_effect = [
            ("a-network_a-version.bna", None),  # ls BNA
            (None, "error"),  # composer card list network-admin
            ("Network install", None),  # composer network install
            ("Network start", None),  # composer network start
            ("Import card", None),  # composer card import network-admin
            ("Network ping", None),  # composer network ping
        ]
        mock_get_pod.side_effect = [mock_pod]
        install_network(self.OPTS)
        mock_get_pod.assert_called_once_with(
            "peer-namespace", "hlc", "hl-composer", verbose=False
        )
        mock_pod.execute.assert_has_calls(
            [
                call("ls /hl_config/blockchain_network"),
                call("composer card list --card an-admin@a-network"),
                call(
                    "composer network install --card PeerAdmin@hlfv1 "
                    + "--archiveFile /hl_config/blockchain_network/a-network_a-version.bna"
                ),
                call(
                    "composer network start "
                    + "--card PeerAdmin@hlfv1 "
                    + "--networkName a-network --networkVersion a-version "
                    + "--networkAdmin an-admin --networkAdminEnrollSecret a-password"
                ),
                call("composer card import --file an-admin@a-network.card"),
                call("composer network ping --card an-admin@a-network"),
            ]
        )
        mock_admin_creds.assert_called_once_with(self.OPTS, "peer_MSP", verbose=False)

    @patch("nephos.composer.install.get_pod")
    @patch("nephos.composer.install.admin_creds")
    def test_install_network_again(self, mock_ca_creds, mock_get_pod):

        mock_pod = Mock()
        mock_pod.execute.side_effect = [
            ("a-network_a-version.bna", None),  # ls BNA
            ("a-network.card", None),  # composer card list network-admin
            ("Network ping", None),  # composer network ping
        ]
        mock_get_pod.side_effect = [mock_pod]
        install_network(self.OPTS, verbose=True)
        mock_get_pod.assert_called_once_with(
            "peer-namespace", "hlc", "hl-composer", verbose=True
        )
        mock_pod.execute.assert_has_calls(
            [
                call("ls /hl_config/blockchain_network"),
                call("composer card list --card an-admin@a-network"),
                call("composer network ping --card an-admin@a-network"),
            ]
        )
        mock_ca_creds.assert_called_once_with(self.OPTS, "peer_MSP", verbose=True)
