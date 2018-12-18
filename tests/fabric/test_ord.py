from unittest import mock
from unittest.mock import call

from fabric.ord import check_ord, setup_ord


class TestCheckOrd:
    @mock.patch('fabric.ord.sleep')
    @mock.patch('fabric.ord.get_pod')
    def test_check_ord(self, mock_get_pod, mock_sleep):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.logs.side_effect = [
            'Not yet started',
            'Not yet started\nStarting orderer'
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_ord('a-namespace', 'a-release')
        assert mock_pod_ex.logs.call_count == 2
        mock_sleep.assert_called_once_with(15)

    @mock.patch('fabric.ord.sleep')
    @mock.patch('fabric.ord.get_pod')
    def test_check_ord_again(self, mock_get_pod, mock_sleep):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.logs.side_effect = [
            'Not yet started\nStarting orderer\nOrderer fetching metadata for all topics from broker'
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_ord('a-namespace', 'a-release', verbose=True)
        assert mock_pod_ex.logs.call_count == 1
        mock_sleep.assert_not_called()


class TestSetupOrd:
    @mock.patch('fabric.ord.helm_upgrade')
    @mock.patch('fabric.ord.helm_install')
    @mock.patch('fabric.ord.check_ord')
    def test_ord(self, mock_check_ord, mock_helm_install, mock_helm_upgrade):
        OPTS = {'core': {'chart_repo': 'a-repo', 'dir_values': './a_dir', 'namespace': 'a-namespace'},
                'orderers': {'names': ['ord0', 'ord1']}}
        setup_ord(OPTS)
        mock_helm_install.assert_has_calls([
            call('a-repo', 'hlf-ord', 'ord0', 'a-namespace',
                 config_yaml='./a_dir/hlf-ord/ord0.yaml', verbose=False),
            call('a-repo', 'hlf-ord', 'ord1', 'a-namespace',
                 config_yaml='./a_dir/hlf-ord/ord1.yaml', verbose=False),
        ])
        mock_helm_upgrade.assert_not_called()
        mock_check_ord.assert_has_calls([
            call('a-namespace', 'ord0', verbose=False),
            call('a-namespace', 'ord1', verbose=False)
        ])

    @mock.patch('fabric.ord.helm_upgrade')
    @mock.patch('fabric.ord.helm_install')
    @mock.patch('fabric.ord.check_ord')
    def test_ord_kafka(self, mock_check_ord, mock_helm_install, mock_helm_upgrade):
        OPTS = {'core': {'chart_repo': 'a-repo', 'dir_values': './a_dir', 'namespace': 'a-namespace'},
                'orderers': {'kafka': {'pod_num': 42}, 'names': ['ord0']}}
        setup_ord(OPTS, verbose=True)
        mock_helm_install.assert_has_calls([
            call('incubator', 'kafka', 'kafka-hlf', 'a-namespace',
                 config_yaml='./a_dir/kafka/kafka-hlf.yaml', pod_num=42, verbose=True),
            call('a-repo', 'hlf-ord', 'ord0', 'a-namespace',
                 config_yaml='./a_dir/hlf-ord/ord0.yaml', verbose=True)
        ])
        mock_helm_upgrade.assert_not_called()
        mock_check_ord.assert_called_once_with('a-namespace', 'ord0', verbose=True)

    @mock.patch('fabric.ord.helm_upgrade')
    @mock.patch('fabric.ord.helm_install')
    @mock.patch('fabric.ord.check_ord')
    def test_ord_upgrade(self, mock_check_ord, mock_helm_install, mock_helm_upgrade):
        OPTS = {'core': {'chart_repo': 'a-repo', 'dir_values': './a_dir', 'namespace': 'a-namespace'},
                'orderers': {'names': ['ord0']}}
        setup_ord(OPTS, upgrade=True)
        mock_helm_install.assert_not_called()
        mock_helm_upgrade.assert_called_once_with(
            'a-repo', 'hlf-ord', 'ord0', 'a-namespace',
            config_yaml='./a_dir/hlf-ord/ord0.yaml', verbose=False
        )
        mock_check_ord.assert_called_once_with('a-namespace', 'ord0', verbose=False)
