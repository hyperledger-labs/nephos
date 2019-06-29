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
        check_ord("a-namespace", "a-release")
        assert mock_pod_ex.logs.call_count == 1
        mock_sleep.assert_not_called()


class TestCheckOrdTls:
    OPTS = {
        "msps": {
            "AlphaMSP": {
                "namespace": "orderer-namespace",
                "orderers": {
                    "nodes": {"an-ord":{}}
                }
            }
        },

    }

    @patch("nephos.fabric.ord.execute")
    def test_check_ord_tls(self, mock_execute):
        mock_execute.side_effect = [("value", None)]
        check_ord_tls(self.OPTS,"an-ord")
        mock_execute.assert_called_once_with(
            'kubectl get cm -n orderer-namespace an-ord-hlf-ord--ord -o jsonpath="{.data.ORDERER_GENERAL_TLS_ENABLED}"'
        )


class TestSetupOrd:
    OPTS = {
        "core": {"chart_repo": "a-repo", "dir_values": "./a_dir"},
        "msps": {
            "AlphaMSP": {
                "namespace": "ord-namespace",
                "orderers": {
                    "nodes": {"ord0":{}}
                }
            }
        },

    }

    # TODO: We should not be able to deploy more than one orderer without Kafka
    @patch("nephos.fabric.ord.get_orderers")
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
        mock_get_orderers
    ):
        OPTS = deepcopy(self.OPTS)
        OPTS["msps"]["AlphaMSP"]["orderers"]["nodes"] = {"ord0":{}, "ord1":{}}
        mock_get_version.side_effect = ["ord-version", "ord-version"]
        mock_helm_extra_vars.side_effect = ["extra-vars-ord0", "extra-vars-ord1"]
        mock_get_orderers.side_effect = [["ord0", "ord1"]]
        setup_ord(OPTS)
        mock_get_orderers.assert_called_once_with(opts=OPTS, msp="AlphaMSP")
        mock_get_version.assert_has_calls(
            [call(OPTS, "hlf-ord"), call(OPTS, "hlf-ord")]
        )
        mock_helm_extra_vars.assert_has_calls(
            [
                call(version="ord-version", config_yaml="./a_dir/AlphaMSP/hlf-ord/ord0.yaml"),
                call(version="ord-version", config_yaml="./a_dir/AlphaMSP/hlf-ord/ord1.yaml"),
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
                    
                ),
                call(
                    "a-repo",
                    "hlf-ord",
                    "ord1",
                    "ord-namespace",
                    extra_vars="extra-vars-ord1",
                    
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
                call("ord-namespace", "ord0"),
                call("ord-namespace", "ord1"),
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
        OPTS["msps"]["AlphaMSP"]["orderers"]["kafka"] = {"name": "kafka-hlf", "pod_num": 42}
        mock_get_version.side_effect = ["kafka-version", "ord-version"]
        mock_helm_extra_vars.side_effect = ["extra-vars-kafka", "extra-vars-ord0"]
        setup_ord(OPTS)
        mock_get_version.assert_has_calls([call(OPTS, "kafka"), call(OPTS, "hlf-ord")])
        mock_helm_extra_vars.assert_has_calls(
            [
                call(
                    version="kafka-version", config_yaml="./a_dir/AlphaMSP/kafka/kafka-hlf.yaml"
                ),
                call(version="ord-version", config_yaml="./a_dir/AlphaMSP/hlf-ord/ord0.yaml"),
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
                    
                ),
                call(
                    "a-repo",
                    "hlf-ord",
                    "ord0",
                    "ord-namespace",
                    extra_vars="extra-vars-ord0",
                    
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
        mock_check_ord.assert_called_once_with("ord-namespace", "ord0")

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
            [call(version="ord-version", config_yaml="./a_dir/AlphaMSP/hlf-ord/ord0.yaml")]
        )
        mock_helm_install.assert_not_called()
        mock_helm_upgrade.assert_called_once_with(
            "a-repo", "hlf-ord", "ord0", extra_vars="extra-vars-ord0"
        )
        mock_check_ord.assert_called_once_with("ord-namespace", "ord0")
        mock_helm_check.assert_has_calls([call("hlf-ord", "ord0", "ord-namespace")])
