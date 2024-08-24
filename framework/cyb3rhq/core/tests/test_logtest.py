# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

with patch('wazuh.common.cyb3rhq_uid'):
    with patch('wazuh.common.cyb3rhq_gid'):
        from cyb3rhq.core.logtest import send_logtest_msg, validate_dummy_logtest
        from cyb3rhq.core.common import LOGTEST_SOCKET
        from cyb3rhq.core.exception import Cyb3rhqError


@pytest.mark.parametrize('params', [
    {'command': 'random_command', 'parameters': {'param1': 'value1'}},
    {'command': None, 'parameters': None}
])
@patch('cyb3rhq.core.logtest.Cyb3rhqSocketJSON.__init__', return_value=None)
@patch('cyb3rhq.core.logtest.Cyb3rhqSocketJSON.send')
@patch('cyb3rhq.core.logtest.Cyb3rhqSocketJSON.close')
@patch('cyb3rhq.core.logtest.create_cyb3rhq_socket_message')
def test_send_logtest_msg(create_message_mock, close_mock, send_mock, init_mock, params):
    """Test `send_logtest_msg` function from module core.logtest.

    Parameters
    ----------
    params : dict
        Params that will be sent to the logtest socket.
    """
    with patch('cyb3rhq.core.logtest.Cyb3rhqSocketJSON.receive',
               return_value={'data': {'response': True, 'output': {'timestamp': '1970-01-01T00:00:00.000000-0200'}}}):
        response = send_logtest_msg(**params)
        init_mock.assert_called_with(LOGTEST_SOCKET)
        create_message_mock.assert_called_with(origin={'name': 'Logtest', 'module': 'framework'}, **params)
        assert response == {'data': {'response': True, 'output': {'timestamp': '1970-01-01T02:00:00.000000Z'}}}


@patch('cyb3rhq.core.logtest.Cyb3rhqSocketJSON.__init__', return_value=None)
@patch('cyb3rhq.core.logtest.Cyb3rhqSocketJSON.send')
@patch('cyb3rhq.core.logtest.Cyb3rhqSocketJSON.close')
@patch('cyb3rhq.core.logtest.create_cyb3rhq_socket_message')
def test_validate_dummy_logtest(create_message_mock, close_mock, send_mock, init_mock):
    with patch('cyb3rhq.core.logtest.Cyb3rhqSocketJSON.receive',
               return_value={'data': {'codemsg': -1}, 'error': 0}):
        with pytest.raises(Cyb3rhqError) as err_info:
            validate_dummy_logtest()

        assert err_info.value.code == 1113
