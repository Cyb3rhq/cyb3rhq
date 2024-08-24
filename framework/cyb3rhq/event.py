# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from cyb3rhq.core.common import QUEUE_SOCKET
from cyb3rhq.core.exception import Cyb3rhqError
from cyb3rhq.core.results import Cyb3rhqResult, AffectedItemsCyb3rhqResult
from cyb3rhq.core.cyb3rhq_queue import Cyb3rhqAnalysisdQueue
from cyb3rhq.rbac.decorators import expose_resources

MSG_HEADER = '1:API-Webhook:'


@expose_resources(actions=["event:ingest"], resources=["*:*:*"], post_proc_func=None)
def send_event_to_analysisd(events: list) -> Cyb3rhqResult:
    """Send events to analysisd through the socket.

    Parameters
    ----------
    events : list
        List of events to send.

    Returns
    -------
    Cyb3rhqResult
        Confirmation message.
    """
    result = AffectedItemsCyb3rhqResult(
        all_msg="All events were forwarded to analisysd",
        some_msg="Some events were forwarded to analisysd",
        none_msg="No events were forwarded to analisysd"
    )

    with Cyb3rhqAnalysisdQueue(QUEUE_SOCKET) as queue:
        for event in events:
            try:
                queue.send_msg(msg_header=MSG_HEADER, msg=event)
                result.affected_items.append(event)
            except Cyb3rhqError as error:
                result.add_failed_item(event, error=error)

    result.total_affected_items = len(result.affected_items)
    return result
