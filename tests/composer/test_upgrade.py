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

    @patch("nephos.composer.upgrade.secret_from_file")
    @patch("nephos.composer.upgrade.print")
    @patch("nephos.composer.upgrade.get_pod")
    def test_upgrade_network(self, mock_get_pod, mock_print, mock_secret_from_file):
        mock_pod_ex = Mock()
        mock_pod_ex.execute.side_effect = [
            ("a-network_a-version.bna", None),
            ("Business network version: another-version", None),
            ("Network install", None),  # network install
            ("Network upgrade", None),  # network upgrade
            ("Business network version: a-version", None),
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        upgrade_network(self.OPTS)
        mock_secret_from_file.assert_called_once_with(
            secret="bna-secret", namespace="peer-ns", verbose=False
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
        mock_print.assert_has_calls(
            [call("another-version"), call("Upgraded to a-version")]
        )

    @patch("nephos.composer.upgrade.secret_from_file")
    @patch("nephos.composer.upgrade.print")
    @patch("nephos.composer.upgrade.get_pod")
    def test_upgrade_network_again(
        self, mock_get_pod, mock_print, mock_secret_from_file
    ):
        mock_pod_ex = Mock()
        mock_pod_ex.execute.side_effect = [
            ("a-network_a-version.bna", None),
            ("Business network version: a-version", None),
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        upgrade_network(self.OPTS, verbose=True)
        mock_secret_from_file.assert_called_once_with(
            secret="bna-secret", namespace="peer-ns", verbose=True
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
        mock_print.assert_has_calls([call("a-version")])
