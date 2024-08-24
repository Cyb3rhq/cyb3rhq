# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import MagicMock, patch

import pytest

with patch('cyb3rhq.core.common.cyb3rhq_uid'):
    with patch('cyb3rhq.core.common.cyb3rhq_gid'):
        sys.modules['cyb3rhq.rbac.orm'] = MagicMock()
        import cyb3rhq.rbac.decorators

        del sys.modules['cyb3rhq.rbac.orm']

        from cyb3rhq.tests.util import RBAC_bypasser

        cyb3rhq.rbac.decorators.expose_resources = RBAC_bypasser
        from cyb3rhq import cluster
        from cyb3rhq.core import common
        from cyb3rhq.core.exception import Cyb3rhqError, Cyb3rhqResourceNotFound
        from cyb3rhq.core.cluster.local_client import LocalClient
        from cyb3rhq.core.results import Cyb3rhqResult

default_config = {'disabled': True, 'node_type': 'master', 'name': 'cyb3rhq', 'node_name': 'node01',
                  'key': '', 'port': 1516, 'bind_addr': '0.0.0.0', 'nodes': ['NODE_IP'], 'hidden': 'no'}


@patch('cyb3rhq.cluster.read_config', return_value=default_config)
def test_read_config_wrapper(mock_read_config):
    """Verify that the read_config_wrapper returns the default configuration."""
    result = cluster.read_config_wrapper()
    assert result.affected_items == [default_config]


@patch('cyb3rhq.cluster.read_config', side_effect=Cyb3rhqError(1001))
def test_read_config_wrapper_exception(mock_read_config):
    """Verify the exceptions raised in read_config_wrapper."""
    result = cluster.read_config_wrapper()
    assert list(result.failed_items.keys())[0] == Cyb3rhqError(1001)


@patch('cyb3rhq.cluster.read_config', return_value=default_config)
def test_node_wrapper(mock_read_config):
    """Verify that the node_wrapper returns the default node information."""
    result = cluster.get_node_wrapper()
    assert result.affected_items == [{'cluster': default_config["name"],
                                      'node': default_config["node_name"],
                                      'type': default_config["node_type"]}]


@patch('cyb3rhq.cluster.get_node', side_effect=Cyb3rhqError(1001))
def test_node_wrapper_exception(mock_get_node):
    """Verify the exceptions raised in get_node_wrapper."""
    result = cluster.get_node_wrapper()
    assert list(result.failed_items.keys())[0] == Cyb3rhqError(1001)


def test_get_status_json():
    """Verify that get_status_json returns the default status information."""
    result = cluster.get_status_json()
    expected = Cyb3rhqResult({'data': {"enabled": "no" if default_config['disabled'] else "yes", "running": "no"}})
    assert result == expected


@pytest.mark.asyncio
@patch('cyb3rhq.core.cluster.local_client.LocalClient.start', side_effect=None)
async def test_get_health_nodes(mock_unix_connection):
    """Verify that get_health_nodes returns the health of all nodes."""

    async def async_mock(lc=None, filter_node=None):
        return {'nodes': {'manager': {'info': {'name': 'master'}}}}

    local_client = LocalClient()
    with patch('cyb3rhq.cluster.get_health', side_effect=async_mock):
        result = await cluster.get_health_nodes(lc=local_client)
    expected = await async_mock()

    assert result.affected_items == [expected['nodes']['manager']]


@pytest.mark.asyncio
async def test_get_nodes_info():
    """Verify that get_nodes_info returns the information of all nodes."""

    async def valid_node(lc=None, filter_node=None):
        return {'items': ['master', 'worker1'], 'totalItems': 2}

    local_client = LocalClient()
    common.cluster_nodes.set(['master', 'worker1', 'worker2'])
    with patch('cyb3rhq.cluster.get_nodes', side_effect=valid_node):
        result = await cluster.get_nodes_info(lc=local_client, filter_node=['master', 'worker1', 'noexists'])
    expected = await valid_node()

    assert result.affected_items == expected['items']
    assert result.total_affected_items == expected['totalItems']
    assert result.failed_items[Cyb3rhqResourceNotFound(1730)] == {'noexists'}
    assert result.total_failed_items == 1


@pytest.mark.parametrize("ruleset_integrity", [
    True,
    False
])
@patch("cyb3rhq.cluster.node_id", new="testing_node")
@pytest.mark.asyncio
async def test_get_ruleset_sync_status(ruleset_integrity):
    """Verify that `get_ruleset_sync_status` function correctly returns node ruleset synchronization status."""
    master_md5 = {'key1': 'value1'}
    with patch("cyb3rhq.cluster.get_node_ruleset_integrity",
               return_value=master_md5 if ruleset_integrity else {}) as ruleset_integrity_mock:
        result = await cluster.get_ruleset_sync_status(master_md5=master_md5)
        assert result.total_affected_items == 1
        assert result.total_failed_items == 0
        assert result.affected_items[0]['name'] == "testing_node"
        assert result.affected_items[0]['synced'] is ruleset_integrity


@patch("cyb3rhq.cluster.node_id", new="testing_node")
@pytest.mark.asyncio
async def test_get_ruleset_sync_status_ko():
    """Verify proper exceptions behavior with `get_ruleset_sync_status`."""
    exc = Cyb3rhqError(1000)
    with patch("cyb3rhq.cluster.get_node_ruleset_integrity", side_effect=exc):
        result = await cluster.get_ruleset_sync_status(master_md5={})
        assert result.total_affected_items == 0
        assert result.total_failed_items == 1
        assert result.failed_items[exc] == {"testing_node"}
