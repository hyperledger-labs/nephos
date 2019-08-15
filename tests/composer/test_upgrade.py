from unittest.mock import call, patch, Mock

from nephos.composer.upgrade import upgrade_network


class TestUpgradeNetwork:
    OPTS = {
        "cas": {"peer-ca": {}},
        "composer": {"secret_bna": "bna-secret"},
        "msps": {
            "peer_MSP": {
                "ca": "peer-ca",
                "namespace": "peer-ns",
                "org_admin": "an-admin",
            }
        },
        "peers": {"msp": "peer_MSP"},
    }

    @patch("nephos.composer.upgrade.secret_create")
    @patch("nephos.composer.upgrade.input_files")
    @patch("nephos.composer.upgrade.logging")
    @patch("nephos.composer.upgrade.get_helm_pod")
    def test_upgrade_network(self, mock_get_pod, mock_log, mock_input_files, mock_secret_create):
        mock_pod_ex = Mock()
        mock_pod_ex.execute.side_effect = [
            ("a-network_a-version.bna", None),
            ("Business network version: another-version", None),
            ("Network install", None),  # network install
            ("Network upgrade", None),  # network upgrade
            ("Business network version: a-version", None),
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        mock_input_files.side_effect = [{"key": "data"}]
        upgrade_network(self.OPTS)
        mock_input_files.assert_called_once_with((None,), clean_key=True)
        mock_secret_create.assert_called_once_with(
            {"key": "data"}, "bna-secret", "peer-ns"
        )
        mock_get_pod.assert_called_once_with(
            "peer-ns", "hlc", "hl-composer", verbose=False
        )
        mock_pod_ex.execute.assert_has_calls(
            [
                call("ls /hl_config/blockchain_network"),
                call("composer network ping --card an-admin@a-network"),
                call(
                    "composer network install --card PeerAdmin@hlfv1 "
                    + "--archiveFile /hl_config/blockchain_network/a-network_a-version.bna"
                ),
                call(
                    "composer network upgrade --card PeerAdmin@hlfv1 "
                    + "--networkName a-network --networkVersion a-version"
                ),
                call("composer network ping --card an-admin@a-network"),
            ]
        )
        mock_log.info.assert_has_calls(
            [call("another-version"), call("Upgraded to a-version")]
        )

    @patch("nephos.composer.upgrade.secret_create")
    @patch("nephos.composer.upgrade.input_files")
    @patch("nephos.composer.upgrade.logging")
    @patch("nephos.composer.upgrade.get_helm_pod")
    def test_upgrade_network_again(self, mock_get_pod, mock_log, mock_input_files, mock_secret_create):
        mock_pod_ex = Mock()
        mock_pod_ex.execute.side_effect = [
            ("a-network_a-version.bna", None),
            ("Business network version: a-version", None),
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        mock_input_files.side_effect = [{"key": "data"}]
        upgrade_network(self.OPTS, verbose=True)
        mock_input_files.assert_called_once_with((None,), clean_key=True)
        mock_secret_create.assert_called_once_with(
            {"key": "data"}, "bna-secret", "peer-ns"
        )
        mock_get_pod.assert_called_once_with(
            "peer-ns", "hlc", "hl-composer", verbose=True
        )
        mock_pod_ex.execute.assert_has_calls(
            [
                call("ls /hl_config/blockchain_network"),
                call("composer network ping --card an-admin@a-network"),
            ]
        )
        mock_log.info.assert_has_calls([call("a-version")])
