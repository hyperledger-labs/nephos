from collections import namedtuple
from unittest.mock import call, patch, MagicMock

from kubernetes.client.rest import ApiException
import pytest

from nephos.helpers.k8s import (
    Executer,
    context_get,
    ns_create,
    ns_read,
    ingress_read,
    pod_check,
    cm_create,
    cm_read,
    get_app_info,
    secret_create,
    secret_read,
    secret_from_file,
)

# NamedTuples for mocking
ConfigMap = namedtuple("ConfigMap", ("data",))
Secret = namedtuple("Secret", ("data",))
IngressHost = namedtuple("IngressHost", ("host",))


class TestExecuter:
    def test_executer_init(self):
        executer = Executer("a-pod", "a-namespace")
        assert executer.pod == "a-pod"
        assert executer.prefix_exec == "kubectl exec a-pod -n a-namespace -- "

    def test_executer_init_container(self):
        executer = Executer("a-pod", "a-namespace", container="a_container")
        assert executer.pod == "a-pod"
        assert (
            executer.prefix_exec
            == "kubectl exec a-pod -n a-namespace --container a_container -- "
        )

    @patch("nephos.helpers.k8s.execute")
    def test_executer_execute(self, mock_execute):
        mock_execute.side_effect = [("result", None)]
        executer = Executer("a_pod", "a-namespace")
        executer.execute("a_command")
        mock_execute.assert_called_once_with(
            "kubectl exec a_pod -n a-namespace -- a_command"
        )

    @patch("nephos.helpers.k8s.execute")
    def test_executer_logs(self, mock_execute):
        mock_execute.side_effect = [("result", None)]
        executer = Executer("a_pod", "a-namespace")
        executer.logs()
        mock_execute.assert_called_once_with(
            "kubectl logs a_pod -n a-namespace --tail=-1"
        )

    @patch("nephos.helpers.k8s.execute")
    def test_executer_logs_tail(self, mock_execute):
        mock_execute.side_effect = [("result", None)]
        executer = Executer(
            "a_pod", "a-namespace", container="a_container"
        )
        executer.logs(tail=10)
        mock_execute.assert_called_once_with(
            "kubectl logs a_pod -n a-namespace --container a_container --tail=10",
            
        )

    @patch("nephos.helpers.k8s.execute")
    def test_executer_logs_sincetime(self, mock_execute):
        mock_execute.side_effect = [("result", None)]
        executer = Executer("a_pod", "a-namespace")
        executer.logs(since_time="1970-01-01T00:00:00Z")
        mock_execute.assert_called_once_with(
            "kubectl logs a_pod -n a-namespace --tail=-1 --since-time='1970-01-01T00:00:00Z'",
            
        )


class TestContextGet:
    CONTEXTS = ({"all": "contexts"}, {"active": "context"})

    @patch("nephos.helpers.k8s.pretty_print")
    @patch("nephos.helpers.k8s.config")
    def test_context_get(self, mock_config, mock_pretty_print):
        mock_config.list_kube_config_contexts.side_effect = [self.CONTEXTS]
        context = context_get()
        mock_config.list_kube_config_contexts.assert_called_once_with()
        mock_pretty_print.assert_called_once()
        assert context == self.CONTEXTS[1]


class TestNsCreate:
    @patch("nephos.helpers.k8s.logging")
    @patch("nephos.helpers.k8s.api")
    @patch("nephos.helpers.k8s.ns_read")
    def test_ns_create_new(self, mock_ns_read, mock_api, mock_log):
        # TODO: We should ideally replicate the correct API exception
        mock_ns_read.side_effect = ApiException()
        ns_create("a-namespace")
        mock_ns_read.assert_called_once_with("a-namespace")
        mock_api.create_namespace.assert_called_once()
        mock_log.info.assert_called_once_with('Created namespace "a-namespace"')

    @patch("nephos.helpers.k8s.logging")
    @patch("nephos.helpers.k8s.api")
    @patch("nephos.helpers.k8s.ns_read")
    def test_ns_create_old(self, mock_ns_read, mock_api, mock_log):
        ns_create("a-namespace")
        mock_ns_read.assert_called_once_with("a-namespace")
        mock_api.create_namespace.assert_not_called()
        mock_log.info.assert_not_called()


class TestNsRead:
    @patch("nephos.helpers.k8s.pretty_print")
    @patch("nephos.helpers.k8s.api")
    def test_ns_read(self, mock_api, mock_pretty_print):
        ns_read("a-namespace")
        mock_api.read_namespace.assert_called_with(name="a-namespace")
        mock_pretty_print.assert_called_once()


class TestIngressRead:
    @patch("nephos.helpers.k8s.pretty_print")
    @patch("nephos.helpers.k8s.api_ext")
    def test_ingress_read(self, mock_api_ext, mock_pretty_print):
        mock_ingress = MagicMock()
        mock_ingress.spec.rules.__iter__.return_value = [
            IngressHost("a-url"),
            IngressHost("another-url"),
        ]
        mock_api_ext.read_namespaced_ingress.side_effect = [mock_ingress]
        ingress_read("an_ingress", "a-namespace")
        mock_api_ext.read_namespaced_ingress.assert_called_once_with(
            name="an_ingress", namespace="a-namespace"
        )
        mock_pretty_print.assert_called_once_with('["a-url", "another-url"]')

    @patch("nephos.helpers.k8s.pretty_print")
    @patch("nephos.helpers.k8s.api_ext")
    def test_ingress_read_fail(self, mock_api_ext, mock_pretty_print):
        mock_api_ext.read_namespaced_ingress.side_effect = [ApiException]
        with pytest.raises(ApiException):
            ingress_read("an_ingress", "a-namespace")
        mock_api_ext.read_namespaced_ingress.assert_called_once_with(
            name="an_ingress", namespace="a-namespace"
        )
        mock_pretty_print.assert_not_called()


class TestPodCheck:
    @patch("nephos.helpers.k8s.sleep")
    @patch("nephos.helpers.k8s.logging")
    @patch("nephos.helpers.k8s.print")
    @patch("nephos.helpers.k8s.execute")
    def test_helm_check(self, mock_execute, mock_print, mock_log, mock_sleep):
        mock_execute.side_effect = [("Pending", None), ("Running", None)]  # Get states
        pod_check("a-namespace", "an-identifier", sleep_interval=15)
        assert mock_execute.call_count == 2
        mock_log.info.assert_has_calls(
            [
                call("Ensuring that all pods are running "),
                call("All pods are running"),
            ]
        )
        mock_print.assert_called_once_with(".", end="", flush=True)
        mock_sleep.assert_called_once_with(15)

    @patch("nephos.helpers.k8s.sleep")
    @patch("nephos.helpers.k8s.logging")
    @patch("nephos.helpers.k8s.print")
    @patch("nephos.helpers.k8s.execute")
    def test_pod_check_podnum(self, mock_execute, mock_print, mock_log, mock_sleep):
        mock_execute.side_effect = [
            ("Pending Running", None),  # Get states
            ("Running Running", None),
        ]
        pod_check("a-namespace", "an_identifier", pod_num=2)
        assert mock_execute.call_count == 2
        mock_log.info.assert_has_calls(
            [
                call("Ensuring that all pods are running "),
                call("All pods are running"),
            ]
        )
        mock_print.assert_called_once_with(".", end="", flush=True)
        mock_sleep.assert_called_once_with(10)


class TestCmCreate:
    @patch("nephos.helpers.k8s.logging")
    @patch("nephos.helpers.k8s.api")
    def test_cm_create(self, mock_api, mock_log):
        cm_create({"a_key": "a_value"}, "a-configmap", "a-namespace")
        mock_api.create_namespaced_config_map.assert_called_once()
        mock_log.info.assert_not_called()

    @patch("nephos.helpers.k8s.logging")
    @patch("nephos.helpers.k8s.api")
    def test_cm_create(self, mock_api, mock_log):
        cm_create({"a_key": "a_value"}, "a-configmap", "a-namespace")
        mock_api.create_namespaced_config_map.assert_called_once()
        mock_log.info.assert_called_once_with(
            "Created ConfigMap a-configmap in namespace a-namespace"
        )


class TestCmRead:
    @patch("nephos.helpers.k8s.pretty_print")
    @patch("nephos.helpers.k8s.api")
    def test_cm_read(self, mock_api, mock_pretty_print):
        mock_api.read_namespaced_config_map.side_effect = [
            ConfigMap({"a_key": "a_value"})
        ]
        cm_read("a_configmap", "a-namespace")
        mock_api.read_namespaced_config_map.assert_called_once_with(
            name="a_configmap", namespace="a-namespace"
        )
        mock_pretty_print.assert_called_once_with('{"a_key": "a_value"}')


class TestSecretCreate:
    @patch("nephos.helpers.k8s.logging")
    @patch("nephos.helpers.k8s.api")
    def test_secret_create(self, mock_api, mock_log):
        secret_create({"a_key": "a_value"}, "a_secret", "a-namespace")
        mock_api.create_namespaced_secret.assert_called_once()
        mock_log.info.assert_called_once_with(
            "Created Secret a_secret in namespace a-namespace"
        )


class TestSecretRead:
    @patch("nephos.helpers.k8s.pretty_print")
    @patch("nephos.helpers.k8s.api")
    def test_secret_read(self, mock_api, mock_pretty_print):
        mock_api.read_namespaced_secret.side_effect = [
            Secret({"a_key": b"YV92YWx1ZQ=="})
        ]
        secret_read("a_secret", "a-namespace")
        mock_api.read_namespaced_secret.assert_called_once_with(
            name="a_secret", namespace="a-namespace"
        )
        mock_pretty_print.assert_called_once_with('{"a_key": "a_value"}')

    @patch("nephos.helpers.k8s.pretty_print")
    @patch("nephos.helpers.k8s.api")
    def test_secret_read_unicode(self, mock_api, mock_pretty_print):
        mock_api.read_namespaced_secret.side_effect = [
            Secret({"a_key": b"YV92YWx1ZYE="})
        ]
        secret_read("a_secret", "a-namespace")
        mock_api.read_namespaced_secret.assert_called_once_with(
            name="a_secret", namespace="a-namespace"
        )
        mock_pretty_print.assert_called_once_with('{"a_key": "a_value"}')


class TestSecretFromFile:
    @patch("nephos.helpers.k8s.open")
    @patch("nephos.helpers.k8s.input_files")
    @patch("nephos.helpers.k8s.secret_create")
    @patch("nephos.helpers.k8s.secret_read")
    def test_secret_from_file(
        self, mock_secret_read, mock_secret_create, mock_input_files, mock_open
    ):
        mock_secret_read.side_effect = ApiException()
        secret_from_file("a_secret", "a-namespace")
        mock_secret_read.assert_called_once()
        mock_secret_create.assert_called_once()
        mock_input_files.assert_called_once()
        mock_open.assert_not_called()

    @patch("nephos.helpers.k8s.open")
    @patch("nephos.helpers.k8s.input_files")
    @patch("nephos.helpers.k8s.secret_create")
    @patch("nephos.helpers.k8s.secret_read")
    def test_secret_from_file_define(
        self, mock_secret_read, mock_secret_create, mock_input_files, mock_open
    ):
        mock_secret_read.side_effect = ApiException()
        secret_from_file("a_secret", "a-namespace", filename="./some_file.txt")
        mock_secret_read.assert_called_once()
        mock_secret_create.assert_called_once()
        mock_input_files.assert_not_called()
        mock_open.assert_called_once()


class TestGetAppInfo:
    @patch("nephos.helpers.k8s.secret_read")
    @patch("nephos.helpers.k8s.ingress_read")
    def test_get_app_info(self, mock_ingress_read, mock_secret_read):
        mock_secret_read.side_effect = [{"API_KEY": "an-api-key"}]
        mock_ingress_read.side_effect = [["a-url"]]
        get_app_info("a-namespace", "an-ingress", "a-secret")
        mock_ingress_read.assert_called_once_with(
            "an-ingress", namespace="a-namespace"
        )

    @patch("nephos.helpers.k8s.secret_read")
    @patch("nephos.helpers.k8s.ingress_read")
    def test_get_app_info_missingsecret(self, mock_ingress_read, mock_secret_read):
        mock_secret_read.side_effect = [ApiException]
        with pytest.raises(ApiException):
            get_app_info("a-namespace", "an-ingress", "a-secret")
        mock_ingress_read.assert_called_once_with(
            "an-ingress", namespace="a-namespace"
        )
        mock_secret_read.assert_called_once_with(
            "a-secret", "a-namespace"
        )

    @patch("nephos.helpers.k8s.secret_read")
    @patch("nephos.helpers.k8s.ingress_read")
    def test_get_app_info_noingress(self, mock_ingress_read, mock_secret_read):
        mock_secret_read.side_effect = [{"CUSTOM_KEY": "an-api-key"}]
        mock_ingress_read.side_effect = [ApiException]
        with pytest.raises(ApiException):
            get_app_info(
                "a-namespace",
                "an-ingress",
                "a-secret",
                secret_key="CUSTOM_KEY",
                
            )
        mock_ingress_read.assert_called_once_with(
            "an-ingress", namespace="a-namespace"
        )
        mock_secret_read.assert_not_called()
