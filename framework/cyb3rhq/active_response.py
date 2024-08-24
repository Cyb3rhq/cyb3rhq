# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from cyb3rhq.core import active_response, common
from cyb3rhq.core.agent import get_agents_info
from cyb3rhq.core.exception import Cyb3rhqException, Cyb3rhqError, Cyb3rhqResourceNotFound
from cyb3rhq.core.cyb3rhq_queue import Cyb3rhqQueue
from cyb3rhq.core.results import AffectedItemsCyb3rhqResult
from cyb3rhq.rbac.decorators import expose_resources


@expose_resources(actions=['active-response:command'], resources=['agent:id:{agent_list}'],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
def run_command(agent_list: list = None, command: str = '', arguments: list = None,
                alert: dict = None) -> AffectedItemsCyb3rhqResult:
    """Run AR command in a specific agent.

    Parameters
    ----------
    agent_list : list
        Agents list that will run the AR command.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Returns
    -------
    AffectedItemsCyb3rhqResult
        Affected items.
    """
    result = AffectedItemsCyb3rhqResult(all_msg='AR command was sent to all agents',
                                      some_msg='AR command was not sent to some agents',
                                      none_msg='AR command was not sent to any agent'
                                      )
    if agent_list:
        with Cyb3rhqQueue(common.AR_SOCKET) as wq:
            system_agents = get_agents_info()
            for agent_id in agent_list:
                try:
                    if agent_id not in system_agents:
                        raise Cyb3rhqResourceNotFound(1701)
                    if agent_id == "000":
                        raise Cyb3rhqError(1703)
                    active_response.send_ar_message(agent_id, wq, command, arguments, alert)
                    result.affected_items.append(agent_id)
                    result.total_affected_items += 1
                except Cyb3rhqException as e:
                    result.add_failed_item(id_=agent_id, error=e)
            result.affected_items.sort(key=int)

    return result
