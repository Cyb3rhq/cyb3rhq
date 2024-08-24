# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from cyb3rhq.core.common import DATABASE_LIMIT
from cyb3rhq.core.results import AffectedItemsCyb3rhqResult
from cyb3rhq.core.task import Cyb3rhqDBQueryTask
from cyb3rhq.rbac.decorators import expose_resources

logger = logging.getLogger('cyb3rhq')


@expose_resources(actions=["task:status"], resources=["*:*:*"], post_proc_kwargs={'exclude_codes': [1817]})
def get_task_status(filters: dict = None, select: list = None, search: dict = None, offset: int = 0,
                    limit: int = DATABASE_LIMIT, sort: dict = None, q: str = None, ) -> AffectedItemsCyb3rhqResult:
    """Read the status of the specified task IDs.

    Parameters
    ----------
    filters : dict
        Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}
    select : dict
        Select fields to return. Format: {"fields":["field1","field2"]}
    search : str
        Search if the string is contained in the db
    offset : int
        First item to return
    limit : int
        Maximum number of items to return
    sort : dict
        Sort the items. Format: {'fields': ['field1', 'field2'], 'order': 'asc|desc'}
    q : str
        Query to filter by

    Returns
    -------
    AffectedItemsCyb3rhqResult
        Tasks's status.
    """
    result = AffectedItemsCyb3rhqResult(all_msg='All specified task\'s status were returned',
                                      some_msg='Some status were not returned',
                                      none_msg='No status was returned')

    with Cyb3rhqDBQueryTask(filters=filters, offset=offset, limit=limit, query=q, sort=sort, search=search,
                          select=select) as db_query:
        data = db_query.run()

    # Fill with zeros the agent_id
    for element in data['items']:
        try:
            element['agent_id'] = str(element['agent_id']).zfill(3)
        except KeyError:
            pass

    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result
