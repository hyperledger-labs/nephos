from copy import deepcopy
from unittest.mock import call, patch, Mock

from nephos.fabric.ord import check_ord, check_ord_tls, setup_ord


class TestCheckOrd:
    @patch("nephos.fabric.ord.sleep")
    @patch("nephos.fabric.ord.get_helm_pod")
    def test_check_ord(self, mock_get_pod, mock_sleep):
        mock_pod_ex = Mock()
        mock_pod_ex.logs.side_effect = [
            "Not yet started",
            "Not yet started\nStarting orderer",
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_ord("a-namespace", "a-release")
        assert mock_pod_ex.logs.call_count == 2
        mock_sleep.assert_called_once_with(15)

    @patch("nephos.fabric.ord.sleep")
    @patch("nephos.fabric.ord.get_helm_pod")
    def test_check_ord_again(self, mock_get_pod, mock_sleep):
        mock_pod_ex = Mock()
        mock_pod_ex.logs.side_effect = [
            "Not yet started\nStarting orderer\nOrderer fetching metadata for all topics from broker"
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_ord("a-namespace", "a-release", verbose=True)
        assert mock_pod_ex.logs.call_count == 1
        mock_sleep.assert_not_called()


class TestCheckOrdTls:
    OPTS = {
        "msps": {"ord_MSP": {"namespace": "orderer-namespace"}},
        "orderers": {"names": ["an-ord"], "msp": "ord_MSP"},
    }

    @patch("nephos.fabric.ord.execute")
    def test_check_ord_tls(self, mock_execute):
        mock_execute.side_effect = [("value", None)]
        check_ord_tls(self.OPTS)
        mock_execute.assert_called_once_with(
            'kubectl get cm -n orderer-namespace an-ord-hlf-ord--ord -o jsonpath="{.data.ORDERER_GENERAL_TLS_ENABLED}"',
            verbose=False,
        )

    @patch("nephos.fabric.ord.execute")
    def test_check_ord_tls_verbose(self, mock_execute):
        mock_execute.side_effect = [("value", None)]
        check_ord_tls(self.OPTS, verbose=True)
        mock_execute.assert_called_once_with(
            'kubectl get cm -n orderer-namespace an-ord-hlf-ord--ord -o jsonpath="{.data.ORDERER_GENERAL_TLS_ENABLED}"',
            verbose=True,
        )


class TestSetupOrd:
    OPTS = {
        "core": {"chart_repo": "a-repo", "dir_values": "./a_dir"},
        "msps": {"ord_MSP": {"namespace": "ord-namespace"}},
        "orderers": {"names": ["ord0"], "msp": "ord_MSP"},
    }

    # TODO: We should not be able to deploy more than one orderer without Kafka
    @patch("nephos.fabric.ord.helm_upgrade")
    @patch("nephos.fabric.ord.helm_install")
    @patch("nephos.fabric.ord.helm_extra_vars")
    @patch("nephos.fabric.ord.helm_check")
    @patch("nephos.fabric.ord.get_version")
    @patch("nephos.fabric.ord.check_ord")
    def test_ord(
        self,
        mock_check_ord,
        mock_get_version,
        mock_helm_check,
        mock_helm_extra_vars,
        mock_helm_install,
        mock_helm_upgrade,
    ):
        OPTS = deepcopy(self.OPTS)
        OPTS["orderers"]["names"] = ["ord0", "ord1"]
        mock_get_version.side_effect = ["ord-version", "ord-version"]
        mock_helm_extra_vars.side_effect = ["extra-vars-ord0", "extra-vars-ord1"]
        setup_ord(OPTS)
        mock_get_version.assert_has_calls(
            [call(OPTS, "hlf-ord"), call(OPTS, "hlf-ord")]
        )
        mock_helm_extra_vars.assert_has_calls(
            [
                call(version="ord-version", config_yaml="./a_dir/hlf-ord/ord0.yaml"),
                call(version="ord-version", config_yaml="./a_dir/hlf-ord/ord1.yaml"),
            ]
        )
        mock_helm_install.assert_has_calls(
            [
                call(
                    "a-repo",
                    "hlf-ord",
                    "ord0",
                    "ord-namespace",
                    extra_vars="extra-vars-ord0",
                    verbose=False,
                ),
                call(
                    "a-repo",
                    "hlf-ord",
                    "ord1",
                    "ord-namespace",
                    extra_vars="extra-vars-ord1",
                    verbose=False,
                ),
            ]
        )
        mock_helm_upgrade.assert_not_called()
        mock_helm_check.assert_has_calls(
            [
                call("hlf-ord", "ord0", "ord-namespace"),
                call("hlf-ord", "ord1", "ord-namespace"),
            ]
        )
        mock_check_ord.assert_has_calls(
            [
                call("ord-namespace", "ord0", verbose=False),
                call("ord-namespace", "ord1", verbose=False),
            ]
        )

    @patch("nephos.fabric.ord.helm_upgrade")
    @patch("nephos.fabric.ord.helm_install")
    @patch("nephos.fabric.ord.helm_extra_vars")
    @patch("nephos.fabric.ord.helm_check")
    @patch("nephos.fabric.ord.get_version")
    @patch("nephos.fabric.ord.check_ord")
    def test_ord_kafka(
        self,
        mock_check_ord,
        mock_get_version,
        mock_helm_check,
        mock_helm_extra_vars,
        mock_helm_install,
        mock_helm_upgrade,
    ):
        OPTS = deepcopy(self.OPTS)
        OPTS["orderers"]["kafka"] = {"name": "kafka-hlf", "pod_num": 42}
        mock_get_version.side_effect = ["kafka-version", "ord-version"]
        mock_helm_extra_vars.side_effect = ["extra-vars-kafka", "extra-vars-ord0"]
        setup_ord(OPTS, verbose=True)
        mock_get_version.assert_has_calls([call(OPTS, "kafka"), call(OPTS, "hlf-ord")])
        mock_helm_extra_vars.assert_has_calls(
            [
                call(
                    version="kafka-version", config_yaml="./a_dir/kafka/kafka-hlf.yaml"
                ),
                call(version="ord-version", config_yaml="./a_dir/hlf-ord/ord0.yaml"),
            ]
        )
        mock_helm_install.assert_has_calls(
            [
                call(
                    "incubator",
                    "kafka",
                    "kafka-hlf",
                    "ord-namespace",
                    extra_vars="extra-vars-kafka",
                    verbose=True,
                ),
                call(
                    "a-repo",
                    "hlf-ord",
                    "ord0",
                    "ord-namespace",
                    extra_vars="extra-vars-ord0",
                    verbose=True,
                ),
            ]
        )
        mock_helm_upgrade.assert_not_called()
        mock_helm_check.assert_has_calls(
            [
                call("kafka", "kafka-hlf", "ord-namespace", pod_num=42),
                call("hlf-ord", "ord0", "ord-namespace"),
            ]
        )
        mock_check_ord.assert_called_once_with("ord-namespace", "ord0", verbose=True)

    @patch("nephos.fabric.ord.helm_upgrade")
    @patch("nephos.fabric.ord.helm_install")
    @patch("nephos.fabric.ord.helm_extra_vars")
    @patch("nephos.fabric.ord.helm_check")
    @patch("nephos.fabric.ord.get_version")
    @patch("nephos.fabric.ord.check_ord")
    def test_ord_upgrade(
        self,
        mock_check_ord,
        mock_get_version,
        mock_helm_check,
        mock_helm_extra_vars,
        mock_helm_install,
        mock_helm_upgrade,
    ):
        mock_get_version.side_effect = ["ord-version"]
        mock_helm_extra_vars.side_effect = ["extra-vars-ord0"]
        setup_ord(self.OPTS, upgrade=True)
        mock_get_version.assert_has_calls([call(self.OPTS, "hlf-ord")])
        mock_helm_extra_vars.assert_has_calls(
            [call(version="ord-version", config_yaml="./a_dir/hlf-ord/ord0.yaml")]
        )
        mock_helm_install.assert_not_called()
        mock_helm_upgrade.assert_called_once_with(
            "a-repo", "hlf-ord", "ord0", extra_vars="extra-vars-ord0", verbose=False
        )
        mock_check_ord.assert_called_once_with("ord-namespace", "ord0", verbose=False)
        mock_helm_check.assert_has_calls([call("hlf-ord", "ord0", "ord-namespace")])
