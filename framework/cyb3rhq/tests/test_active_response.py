#!/usr/bin/env python
# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('cyb3rhq.core.common.cyb3rhq_uid'):
    with patch('cyb3rhq.core.common.cyb3rhq_gid'):
        sys.modules['cyb3rhq.rbac.orm'] = MagicMock()
        import cyb3rhq.rbac.decorators
        from cyb3rhq.tests.util import RBAC_bypasser

        del sys.modules['cyb3rhq.rbac.orm']
        cyb3rhq.rbac.decorators.expose_resources = RBAC_bypasser

        from cyb3rhq.active_response import run_command
        from cyb3rhq.core.tests.test_active_response import agent_config, agent_info_exception_and_version

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'etc', 'shared', 'ar.conf')
full_agent_list = ['000', '001', '002', '003', '004', '005', '006', '007', '008']


# Tests

@pytest.mark.parametrize('message_exception, send_exception, agent_id, command, arguments, alert, version', [
    (1701, None, ['999'], 'restart-cyb3rhq0', [], None, 'Cyb3rhq v4.0.0'),
    (1703, None, ['000'], 'restart-cyb3rhq0', [], None, 'Cyb3rhq v4.0.0'),
    (1650, None, ['001'], None, [], None, 'Cyb3rhq v4.0.0'),
    (1652, None, ['002'], 'random', [], None, 'Cyb3rhq v4.0.0'),
    (None, 1707, ['003'], 'restart-cyb3rhq0', [], None, None),
    (None, 1750, ['004'], 'restart-cyb3rhq0', [], None, 'Cyb3rhq v4.0.0'),
    (None, None, ['005'], 'restart-cyb3rhq0', [], None, 'Cyb3rhq v4.0.0'),
    (None, None, ['006'], '!custom-ar', [], None, 'Cyb3rhq v4.0.0'),
    (None, None, ['007'], 'restart-cyb3rhq0', ["arg1", "arg2"], None, 'Cyb3rhq v4.0.0'),
    (None, None, ['001', '002', '003', '004', '005', '006'], 'restart-cyb3rhq0', [], None, 'Cyb3rhq v4.0.0'),
    (None, None, ['001'], 'restart-cyb3rhq0', ["arg1", "arg2"], None, 'Cyb3rhq v4.2.0'),
    (None, None, ['002'], 'restart-cyb3rhq0', [], None, 'Cyb3rhq v4.2.1'),
])
@patch("cyb3rhq.core.cyb3rhq_queue.Cyb3rhqQueue._connect")
@patch("cyb3rhq.syscheck.Cyb3rhqQueue._send", return_value='1')
@patch("cyb3rhq.core.cyb3rhq_queue.Cyb3rhqQueue.close")
@patch('cyb3rhq.core.common.AR_CONF', new=test_data_path)
@patch('cyb3rhq.active_response.get_agents_info', return_value=full_agent_list)
def test_run_command(mock_get_agents_info, mock_close, mock_send, mock_conn, message_exception,
                     send_exception, agent_id, command, arguments, alert, version):
    """Verify the proper operation of active_response module.

    Parameters
    ----------
    message_exception : int
        Exception code expected when calling create_message.
    send_exception : int
        Exception code expected when calling send_command.
    agent_id : list
        Agents on which to execute the Active response command.
    command : string
        Command to be executed on the agent.
    arguments : list
        Arguments of the command.
    custom : boolean
        True if command is a script.
    version : list
        List with the agent version to test whether the message sent was the correct one or not.
    """
    with patch('cyb3rhq.core.agent.Agent.get_basic_information',
               return_value=agent_info_exception_and_version(send_exception, version)):
        with patch('cyb3rhq.core.agent.Agent.get_config', return_value=agent_config(send_exception)):
            if message_exception:
                ret = run_command(agent_list=agent_id, command=command, arguments=arguments, alert=alert)
                assert ret.render()['data']['failed_items'][0]['error']['code'] == message_exception
            else:
                ret = run_command(agent_list=agent_id, command=command, arguments=arguments, alert=alert)
                if send_exception:
                    assert ret.render()['message'] == 'AR command was not sent to any agent'
                    assert ret.render()['data']['failed_items'][0]['error']['code'] == send_exception
                else:
                    assert ret.render()['message'] == 'AR command was sent to all agents'
