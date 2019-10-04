from collections import namedtuple
from unittest.mock import call, patch, MagicMock

from kubernetes.client.rest import ApiException
import pytest

from nephos.helpers.executer import Executer

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

    @patch("nephos.helpers.executer.execute")
    def test_executer_execute(self, mock_execute):
        mock_execute.side_effect = [("result", None)]
        executer = Executer("a_pod", "a-namespace")
        executer.execute("a_command")
        mock_execute.assert_called_once_with(
            "kubectl exec a_pod -n a-namespace -- a_command"
        )

    @patch("nephos.helpers.executer.execute")
    def test_executer_logs(self, mock_execute):
        mock_execute.side_effect = [("result", None)]
        executer = Executer("a_pod", "a-namespace")
        executer.logs()
        mock_execute.assert_called_once_with(
            "kubectl logs a_pod -n a-namespace --tail=-1"
        )

    @patch("nephos.helpers.executer.execute")
    def test_executer_logs_tail(self, mock_execute):
        mock_execute.side_effect = [("result", None)]
        executer = Executer("a_pod", "a-namespace", container="a_container")
        executer.logs(tail=10)
        mock_execute.assert_called_once_with(
            "kubectl logs a_pod -n a-namespace --container a_container --tail=10"
        )

    @patch("nephos.helpers.executer.execute")
    def test_executer_logs_sincetime(self, mock_execute):
        mock_execute.side_effect = [("result", None)]
        executer = Executer("a_pod", "a-namespace")
        executer.logs(since_time="1970-01-01T00:00:00Z")
        mock_execute.assert_called_once_with(
            "kubectl logs a_pod -n a-namespace --tail=-1 --since-time='1970-01-01T00:00:00Z'"
        )
