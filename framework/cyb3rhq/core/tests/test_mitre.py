#!/usr/bin/env python
# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

from cyb3rhq.tests.util import InitWDBSocketMock

with patch('cyb3rhq.core.common.cyb3rhq_uid'):
    with patch('cyb3rhq.core.common.cyb3rhq_gid'):
        from cyb3rhq.core.mitre import *


@patch('cyb3rhq.core.utils.Cyb3rhqDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_Cyb3rhqDBQueryMitreMetadata(mock_wdb):
    """Verify that the method connects correctly to the database and returns the correct type."""
    db_query = Cyb3rhqDBQueryMitreMetadata()
    data = db_query.run()

    assert isinstance(db_query, Cyb3rhqDBQueryMitre) and isinstance(data, dict)


@pytest.mark.parametrize('wdb_query_class', [
    Cyb3rhqDBQueryMitreGroups,
    Cyb3rhqDBQueryMitreMitigations,
    Cyb3rhqDBQueryMitreReferences,
    Cyb3rhqDBQueryMitreTactics,
    Cyb3rhqDBQueryMitreTechniques,
    Cyb3rhqDBQueryMitreSoftware

])
@patch('cyb3rhq.core.utils.Cyb3rhqDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_Cyb3rhqDBQueryMitre_classes(mock_wdb, wdb_query_class):
    """Verify that the method connects correctly to the database and returns the correct types."""
    db_query = wdb_query_class()
    data = db_query.run()

    assert isinstance(db_query, Cyb3rhqDBQueryMitre) and isinstance(data, dict)

    # All items have all the related_items (relation_fields) and their type is list
    try:
        assert all(
            isinstance(data_item[related_item], list) for related_item in db_query.relation_fields for data_item in
            data['items'])
    except KeyError:
        pytest.fail("Related item not found in data obtained from query")


@pytest.mark.parametrize('mitre_wdb_query_class', [
    Cyb3rhqDBQueryMitreGroups,
    Cyb3rhqDBQueryMitreMitigations,
    Cyb3rhqDBQueryMitreReferences,
    Cyb3rhqDBQueryMitreTactics,
    Cyb3rhqDBQueryMitreTechniques,
    Cyb3rhqDBQueryMitreSoftware
])
@patch('cyb3rhq.core.utils.Cyb3rhqDBConnection')
def test_get_mitre_items(mock_wdb, mitre_wdb_query_class):
    """Test get_mitre_items function."""
    info, data = get_mitre_items(mitre_wdb_query_class)

    db_query_to_compare = mitre_wdb_query_class()

    assert isinstance(info['allowed_fields'], set) and info['allowed_fields'] == set(
        db_query_to_compare.fields.keys()).union(
        db_query_to_compare.relation_fields).union(db_query_to_compare.extra_fields)
    assert isinstance(info['min_select_fields'], set) and info[
        'min_select_fields'] == db_query_to_compare.min_select_fields
