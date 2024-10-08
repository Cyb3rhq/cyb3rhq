#!/usr/bin/env python
# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from sqlite3 import connect
from unittest.mock import patch, MagicMock

import pytest

from cyb3rhq.tests.util import InitWDBSocketMock

with patch('cyb3rhq.core.common.cyb3rhq_uid'):
    with patch('cyb3rhq.core.common.cyb3rhq_gid'):
        sys.modules['cyb3rhq.rbac.orm'] = MagicMock()
        import cyb3rhq.rbac.decorators

        del sys.modules['cyb3rhq.rbac.orm']

        from cyb3rhq.tests.util import RBAC_bypasser

        cyb3rhq.rbac.decorators.expose_resources = RBAC_bypasser
        from cyb3rhq.syscheck import run, clear, last_scan, files
        from cyb3rhq.syscheck import AffectedItemsCyb3rhqResult
        from cyb3rhq import Cyb3rhqError, Cyb3rhqInternalError
        from cyb3rhq.core import common

callable_list = list()
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_agent_data_path = os.path.join(test_data_path, 'agent')


# Retrieve used parameters in mocked method
def set_callable_list(*params, **kwargs):
    callable_list.append((params, kwargs))


# Get a fake database
def get_fake_syscheck_db(sql_file):
    def create_memory_db(*args, **kwargs):
        syscheck_db = connect(':memory:')
        cur = syscheck_db.cursor()
        with open(os.path.join(test_data_path, sql_file)) as f:
            cur.executescript(f.read())
        return syscheck_db

    return create_memory_db


test_result = [
    {'affected_items': ['001', '002'], 'total_affected_items': 2, 'failed_items': {}, 'total_failed_items': 0},
    {'affected_items': ['003', '008'], 'total_affected_items': 2, 'failed_items': {'001'}, 'total_failed_items': 1},
    {'affected_items': ['001'], 'total_affected_items': 1, 'failed_items': {'002', '003'},
     'total_failed_items': 2},
    # This result is used for exceptions
    {'affected_items': [], 'total_affected_items': 0, 'failed_items': {'001'}, 'total_failed_items': 1},
]


@pytest.mark.parametrize('agent_list, failed_items, status_list, expected_result', [
    (['002', '001'], [{'items': []}], ['active', 'active'], test_result[0]),
    (['003', '001', '008'], [{'items': [{'id': '001', 'status': ['disconnected']}]}],
     ['active', 'disconnected', 'active'], test_result[1]),
    (['001', '002', '003'], [{'items': [{'id': '002', 'status': ['disconnected']},
                                        {'id': '003', 'status': ['disconnected']}]}],
     ['active', 'disconnected', 'disconnected'], test_result[2]),
])
@patch('cyb3rhq.core.common.CLIENT_KEYS', new=os.path.join(test_agent_data_path, 'client.keys'))
@patch('cyb3rhq.syscheck.Cyb3rhqDBQueryAgents.__exit__')
@patch('cyb3rhq.syscheck.Cyb3rhqDBQueryAgents.__init__', return_value=None)
@patch('cyb3rhq.syscheck.Cyb3rhqQueue._connect')
@patch('cyb3rhq.syscheck.Cyb3rhqQueue.send_msg_to_agent', side_effect=set_callable_list)
@patch('cyb3rhq.syscheck.Cyb3rhqQueue.close')
def test_syscheck_run(close_mock, send_mock, connect_mock, agent_init_mock, agent_exit_mock,
                      agent_list, failed_items, status_list, expected_result):
    """Test function `run` from syscheck module.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    agent_list : list
        List of failed items.
    status_list : list
        List of agent statuses.
    expected_result : list
        List of dicts with expected results for every test.
    """
    with patch('cyb3rhq.syscheck.Cyb3rhqDBQueryAgents.run', return_value=failed_items[0]):
        result = run(agent_list=agent_list)
        for args, kwargs in callable_list:
            assert (isinstance(a, str) for a in args)
            assert (isinstance(k, str) for k in kwargs)
        assert isinstance(result, AffectedItemsCyb3rhqResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@pytest.mark.parametrize('agent_version', ('v3.11.9',))
@pytest.mark.parametrize('agent_list, expected_result, agent_info_list', [
    (['001', '002'], test_result[0], ['001', '002']),
    (['003', '001', '008'], test_result[1], ['003', '008'])
])
@patch('cyb3rhq.core.wdb.Cyb3rhqDBConnection.__init__', return_value=None)
@patch('cyb3rhq.core.wdb.Cyb3rhqDBConnection.execute', return_value=None)
@patch('cyb3rhq.core.wdb.Cyb3rhqDBConnection.close')
def test_syscheck_clear(wdb_close_mock, wdb_execute_mock, wdb_init_mock, agent_list, expected_result, agent_info_list,
                        agent_version):
    """Test function `clear` from syscheck module.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    expected_result : list
        List of dicts with expected results for every test.
    agent_info_list : list
        List of agent IDs that `syscheck.get_agents_info` will return when mocked.
    """
    with patch('cyb3rhq.syscheck.get_agents_info', return_value=set(agent_info_list)), \
            patch('cyb3rhq.syscheck.Cyb3rhqDBQueryAgents') as mock_wdbqa:
        mock_wdbqa.return_value.run.return_value = {
            'items': [{'id': ag_id, 'version': agent_version} for ag_id in agent_info_list]}

        result = clear(agent_list=agent_list)
        assert isinstance(result, AffectedItemsCyb3rhqResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']
        wdb_close_mock.assert_called()


@pytest.mark.parametrize('agent_version, expected_version_errcode', [
    ('v3.12.0', 1760),
    ('Cyb3rhq v4.2.0', 1760),
    (None, 1015)
])
@pytest.mark.parametrize('agent_list, expected_result, agent_info_list', [
    (['001'], test_result[3], ['001']),
])
@patch('cyb3rhq.core.wdb.Cyb3rhqDBConnection.__init__', return_value=None)
@patch('cyb3rhq.core.wdb.Cyb3rhqDBConnection.execute', side_effect=Cyb3rhqError(1000))
@patch('cyb3rhq.core.wdb.Cyb3rhqDBConnection.close')
def test_syscheck_clear_exception(wdb_close_mock, execute_mock, wdb_init_mock, agent_list, expected_result,
                                  agent_info_list, agent_version, expected_version_errcode):
    """Test function `clear` from syscheck module.

    It will force an exception.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    expected_result : list
        List of dicts with expected results for every test.
    agent_info_list : list
        List of agent IDs that `syscheck.get_agents_info` will return when mocked.
    """
    with patch('cyb3rhq.syscheck.get_agents_info', return_value=set(agent_info_list)), \
            patch('cyb3rhq.syscheck.Cyb3rhqDBQueryAgents') as mock_wdbqa:
        mock_wdbqa.return_value.run.return_value = {
            'items': [{'id': ag_id, 'version': agent_version} for ag_id in agent_info_list]}

        result = clear(agent_list=agent_list)

        w_error = next(iter(result.failed_items))
        assert expected_version_errcode == w_error.code
        assert isinstance(result, AffectedItemsCyb3rhqResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@pytest.mark.parametrize('agent_id, cyb3rhq_version', [
    (['001'], {'version': 'Cyb3rhq v3.6.0'}),
    (['002'], {'version': 'Cyb3rhq v3.8.3'}),
    (['005'], {'version': 'Cyb3rhq v3.5.3'}),
    (['006'], {'version': 'Cyb3rhq v3.9.4'}),
    (['004'], {}),
])
@patch('cyb3rhq.core.utils.path.exists', return_value=True)
@patch('sqlite3.connect', side_effect=get_fake_syscheck_db('schema_syscheck_test.sql'))
@patch("cyb3rhq.syscheck.Cyb3rhqDBConnection.execute", return_value=[{'end': '', 'start': ''}])
@patch('socket.socket.connect')
def test_syscheck_last_scan(socket_mock, wdb_conn_mock, db_mock, exists_mock, agent_id, cyb3rhq_version):
    """Test function `last_scan` from syscheck module.

    Parameters
    ----------
    agent_id : list
        Agent ID.
    cyb3rhq_version : dict
        Dict with the Cyb3rhq version to be applied.
    """
    with patch('cyb3rhq.syscheck.Agent.get_basic_information', return_value=cyb3rhq_version):
        result = last_scan(agent_id)
        assert isinstance(result, AffectedItemsCyb3rhqResult)
        assert isinstance(result.affected_items, list)
        assert result.total_affected_items == 1


@pytest.mark.parametrize('agent_id, select, filters, distinct, q', [
    (['001'], None, None, None, None),
    (['002'], ['file', 'size', 'mtime'], None, False, None),
    (['003'], None, {'inode': '15470536'}, True, None),
    (['004'], ['file', 'size'], {'hash': '15470536'}, False, None),
    (['005'], None, {'date': '2019-05-21 12:10:20'}, True, None),
    (['006'], None, {'type': 'registry_key'}, True, None),
    (['007'], ['file', 'arch', 'value.name', 'value.type'], None, True, None),
    (['008'], ['file', 'value.name'], None, True, None),
    (['009'], ['value.name'], None, True, None),
    (['000'], ['attributes'], None, True, None),
    (['000'], None,
     {'file': 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\SecureTimeLimits\\RunTime'}, True,
     None),
    (['000'], None, None, False, "file=HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
                                 "\\Interfaces\\{4473f692-67de-480d-a481-6de3e4a2813b};(type=file,type=registry_key)")
])
@patch('cyb3rhq.core.utils.path.exists', return_value=True)
@patch('socket.socket.connect')
@patch('cyb3rhq.core.common.WDB_PATH', new=test_data_path)
def test_syscheck_files(socket_mock, exists_mock, agent_id, select, filters, distinct, q):
    """Test function `files` from syscheck module.

    Parameters
    ----------
    agent_id : list
        Agent ID.
    select :
        List of parameters to show from the query.
    filters : dict
        Dict to filter out the result.
    distinct : bool
        True if all response items must be unique
    """
    select_list = ['date', 'mtime', 'file', 'size', 'perm', 'uname', 'gname', 'md5', 'sha1', 'sha256', 'inode', 'gid',
                   'uid', 'type', 'changes', 'attributes', 'arch', 'value.name', 'value.type']
    nested_fields = ['value']

    with patch('cyb3rhq.core.utils.Cyb3rhqDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_syscheck_test.sql')
        select = select if select else select_list
        result = files(agent_id, select=select, filters=filters, q=q)
        assert isinstance(result, AffectedItemsCyb3rhqResult)
        assert isinstance(result.affected_items, list)
        # Use flag for min_select_field, if file not in select, len(item.keys()) = len(select) + 1
        flag_select_min = 1 if 'file' not in select else 0
        for item in result.affected_items:
            # Use flag for nested_fields in order to compare select and item.keys() lengths
            flag_nested = 0
            for nested_field in nested_fields:
                if nested_field in item.keys():
                    flag_nested += sum(1 for i in select if i.startswith(nested_field)) - 1
            assert len(select) + flag_select_min == len(item.keys()) + flag_nested
            assert (param in select for param in item.keys())
        assert not any(result.affected_items.count(item) > 1 for item in result.affected_items) if distinct else True
        if filters:
            for key, value in filters.items():
                assert (item[key] == value for item in result.affected_items)
