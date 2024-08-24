# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

from cyb3rhq.core import common
from cyb3rhq.core.agent import Agent
from cyb3rhq.core.cluster.cluster import get_node
from cyb3rhq.core.cluster.utils import read_cluster_config
from cyb3rhq.core.exception import Cyb3rhqError
from cyb3rhq.core.utils import Cyb3rhqVersion
from cyb3rhq.core.cyb3rhq_queue import Cyb3rhqQueue
from cyb3rhq.core.cyb3rhq_socket import create_cyb3rhq_socket_message


def get_commands() -> list:
    """Get the available commands.

    Returns
    -------
    list
        List with the available commands.
    """
    commands = list()
    with open(common.AR_CONF) as f:
        for line in f:
            cmd = line.split(" - ")[0]
            commands.append(cmd)

    return commands


def shell_escape(command: str) -> str:
    """Escape some characters in the command before sending it.

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts with !, then it refers to a script name instead of a
        command name.

    Returns
    -------
    str
        Command with escape characters.
    """
    shell_escapes = \
        ['"', '\'', '\t', ';', '`', '>', '<', '|', '#', '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')']
    for shell_esc_char in shell_escapes:
        command = command.replace(shell_esc_char, "\\" + shell_esc_char)

    return command


class ARMessageBuilder:
    @staticmethod
    def can_handle(agent_version: str) -> bool:
        """Check if the message builder can handle the given agent version.

        Parameters
        ----------
        agent_version : str
            The version of the agent.

        Returns
        -------
        bool
            True if the message builder can handle the agent version, False otherwise.
        """
        raise NotImplementedError

    def create_message(self, command: str = '', arguments: list = None, alert: dict = None) -> str:
        """Create the message with the Active Response format that will be sent to the socket.

        Parameters
        ----------
        command : str
            Command running in the agent. If this value starts with !, then it refers to a script name instead of a
            command name.
        arguments : list
            Command arguments.
        alert : dict
            Alert data that will be sent with the AR command.

        Returns
        -------
        str
            Message that will be sent to the socket.
        """
        raise NotImplementedError

    @classmethod
    def choose_builder(cls, agent_version: str):
        """Choose the appropriate message builder based on the agent version.

        Parameters
        ----------
        agent_version : str
            The version of the agent.

        Returns
        -------
        ARMessageBuilder
            An instance of the chosen message builder.

        Raises
        ------
        Cyb3rhqError(1000)
            If no suitable message builder is found for the agent version.
        """

        for subclass in cls.__subclasses__():
            if subclass.can_handle(agent_version):
                return subclass()

        raise Cyb3rhqError(1000, "No suitable message builder found for agent version: {}".format(agent_version))

    def validate_command(self, command: str):
        """Validate the command for Active Response.

        Parameters
        ----------
        command : str
            Command running in the agent. If this value starts with !, then it refers to a script name instead of a command
            name.

        Raises
        ------
        Cyb3rhqError(1650)
            If the command is not specified.
        Cyb3rhqError(1652)
            If the command is not custom and the command is not one of the available commands.
        """
        if not command:
            raise Cyb3rhqError(1650)

        if not command.startswith('!'):
            commands = get_commands()
            if command not in commands:
                raise Cyb3rhqError(1652)


class ARStrMessage(ARMessageBuilder):
    @staticmethod
    def can_handle(agent_version: str) -> bool:
        """Check if the ARStrMessage can handle the given agent version.

        Parameters
        ----------
        agent_version : str
            The version of the agent.

        Returns
        -------
        bool
            True if ARStrMessage can handle the agent version, False otherwise.
        """
        return Cyb3rhqVersion(agent_version) < Cyb3rhqVersion(common.AR_LEGACY_VERSION)

    def create_message(self, command: str = '', arguments: list = None, alert: dict = None) -> str:
        """Create the message with the Active Response format that will be sent to the socket.

        Parameters
        ----------
        command : str
            Command running in the agent. If this value starts with !, then it refers to a script name instead of a command
            name.
        arguments : list
            Command arguments.
        alert : dict
            Alert data that will be sent with the AR command.

        Raises
        ------
        Cyb3rhqError(1650)
            If the command is not specified.
        Cyb3rhqError(1652)
            If the command is not custom and the command is not one of the available commands.

        Returns
        -------
        str
            Message that will be sent to the socket.
        """
        self.validate_command(command)

        msg_queue = command
        msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments) if arguments else " - -"

        return msg_queue


class ARJsonMessage(ARMessageBuilder):
    @staticmethod
    def can_handle(agent_version: str) -> bool:
        """Check if the ARJsonMessage can handle the given agent version.

        Parameters
        ----------
        agent_version : str
            The version of the agent.

        Returns
        -------
        bool
            True if ARJsonMessage can handle the agent version, False otherwise.
        """
        return Cyb3rhqVersion(agent_version) >= Cyb3rhqVersion(common.AR_LEGACY_VERSION)

    def create_message(self, command: str = '', arguments: list = None, alert: dict = None) -> str:
        """Create the message with the Active Response format that will be sent to the socket.

        Parameters
        ----------
        command : str
            Command running in the agent. If this value starts by !, then it refers to a script name instead of a command
            name.
        arguments : list
            Command arguments.
        alert : dict
            Alert data that will be sent with the AR command.

        Raises
        ------
        Cyb3rhqError(1650)
            If the command is not specified.
        Cyb3rhqError(1652)
            If the command is not custom and the command is not one of the available commands.

        Returns
        -------
        str
            Message that will be sent to the socket.
        """
        self.validate_command(command)

        cluster_enabled = not read_cluster_config()['disabled']
        node_name = get_node().get('node') if cluster_enabled else None

        msg_queue = json.dumps(
            create_cyb3rhq_socket_message(origin={'name': node_name, 'module': common.origin_module.get()},
                                        command=command,
                                        parameters={'extra_args': arguments if arguments else [],
                                                    'alert': alert if alert else {}}))

        return msg_queue


def send_ar_message(agent_id: str = '', wq: Cyb3rhqQueue = None, command: str = '', arguments: list = None,
                    alert: dict = None) -> None:
    """Send the active response message to the agent.

    Parameters
    ----------
    agent_id : str
        ID specifying the agent where the msg_queue will be sent to.
    wq : Cyb3rhqQueue
        Used for the active response messages.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Raises
    ------
    Cyb3rhqError(1707)
        If the agent with ID agent_id is not active.
    Cyb3rhqError(1750)
        If active response is disabled in the specified agent.
    """
    # Agent basic information
    agent_info = Agent(agent_id).get_basic_information()

    # Check if agent is active
    if agent_info['status'].lower() != 'active':
        raise Cyb3rhqError(1707)

    # Once we know the agent is active, store version
    agent_version = agent_info['version']

    # Check if AR is enabled
    agent_conf = Agent(agent_id).get_config('com', 'active-response', agent_version)
    if agent_conf['active-response']['disabled'] == 'yes':
        raise Cyb3rhqError(1750)

    # Create classic msg or JSON msg depending on the agent version
    message_builder = ARMessageBuilder.choose_builder(agent_version)
    msg_queue = message_builder.create_message(command=command, arguments=arguments, alert=alert)

    wq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=Cyb3rhqQueue.AR_TYPE)



