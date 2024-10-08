# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from contextvars import ContextVar
from copy import deepcopy
from functools import lru_cache, wraps
from grp import getgrnam
from multiprocessing import Event
from pwd import getpwnam
from typing import Any, Dict


# ===================================================== Functions ======================================================
@lru_cache(maxsize=None)
def find_cyb3rhq_path() -> str:
    """Get the Cyb3rhq installation path.

    Returns
    -------
    str
        Path where Cyb3rhq is installed or empty string if there is no framework in the environment.
    """
    abs_path = os.path.abspath(os.path.dirname(__file__))
    allparts = []
    while 1:
        parts = os.path.split(abs_path)
        if parts[0] == abs_path:  # sentinel for absolute paths.
            allparts.insert(0, parts[0])
            break
        elif parts[1] == abs_path:  # sentinel for relative paths.
            allparts.insert(0, parts[1])
            break
        else:
            abs_path = parts[0]
            allparts.insert(0, parts[1])

    cyb3rhq_path = ''
    try:
        for i in range(0, allparts.index('framework')):
            cyb3rhq_path = os.path.join(cyb3rhq_path, allparts[i])
    except ValueError:
        pass

    return cyb3rhq_path


def cyb3rhq_uid() -> int:
    """Retrieve the numerical user ID for the cyb3rhq user.

    Returns
    -------
    int
        Numerical user ID.
    """
    return getpwnam(USER_NAME).pw_uid if globals()['_CYB3RHQ_UID'] is None else globals()['_CYB3RHQ_UID']


def cyb3rhq_gid() -> int:
    """Retrieve the numerical group ID for the cyb3rhq group.

    Returns
    -------
    int
        Numerical group ID.
    """
    return getgrnam(GROUP_NAME).gr_gid if globals()['_CYB3RHQ_GID'] is None else globals()['_CYB3RHQ_GID']


def context_cached(key: str = '') -> Any:
    """Save the result of the decorated function in a cache.

    Next calls to the decorated function returns the saved result saving time and resources. The cache gets
    invalidated at the end of the request.

    Parameters
    ----------
    key : str
        Part of the cache entry identifier. The identifier will be the key + args + kwargs.

    Returns
    -------
    Any
        The result of the first call to the decorated function.

    Notes
    -----
    The returned object will be a deep copy of the cached one.
    """

    def decorator(func) -> Any:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            cached_key = json.dumps({'key': key, 'args': args, 'kwargs': kwargs})
            if cached_key not in _context_cache:
                _context_cache[cached_key] = ContextVar(cached_key, default=None)
            if _context_cache[cached_key].get() is None:
                result = func(*args, **kwargs)
                _context_cache[cached_key].set(result)
            return deepcopy(_context_cache[cached_key].get())

        return wrapper

    return decorator


def reset_context_cache() -> None:
    """Reset context cache."""

    for context_var in _context_cache.values():
        context_var.set(None)


def get_context_cache() -> dict:
    """Get the context cache.

    Returns
    -------
    dict
        Dictionary with the context variables representing the cache.
    """

    return _context_cache


# ================================================= Context variables ==================================================
rbac: ContextVar[Dict] = ContextVar('rbac', default={'rbac_mode': 'black'})
current_user: ContextVar[str] = ContextVar('current_user', default='')
broadcast: ContextVar[bool] = ContextVar('broadcast', default=False)
cluster_nodes: ContextVar[list] = ContextVar('cluster_nodes', default=list())
origin_module: ContextVar[str] = ContextVar('origin_module', default='framework')
try:
    mp_pools: ContextVar[Dict] = ContextVar('mp_pools', default={
        'process_pool': ProcessPoolExecutor(max_workers=1),
        'authentication_pool': ProcessPoolExecutor(max_workers=1),
        'events_pool': ProcessPoolExecutor(max_workers=1)
    })
# Handle exception when the user running Cyb3rhq cannot access /dev/shm.
except (FileNotFoundError, PermissionError):
    mp_pools: ContextVar[Dict] = ContextVar('mp_pools', default={
        'thread_pool': ThreadPoolExecutor(max_workers=1)
    })
_context_cache = dict()


# =========================================== Cyb3rhq constants and variables ============================================
# Clear cache event.
cache_event = Event()
_CYB3RHQ_UID = None
_CYB3RHQ_GID = None
GROUP_NAME = 'cyb3rhq'
USER_NAME = 'cyb3rhq'
CYB3RHQ_PATH = find_cyb3rhq_path()


# ============================================= Cyb3rhq constants - Commands =============================================
CHECK_CONFIG_COMMAND = 'check-manager-configuration'
RESTART_CYB3RHQ_COMMAND = 'restart-cyb3rhq'


# =========================================== Cyb3rhq constants - Date format ============================================
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DECIMALS_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# ============================================ Cyb3rhq constants - Extensions ============================================
RULES_EXTENSION = '.xml'
DECODERS_EXTENSION = '.xml'
LISTS_EXTENSION = ''
COMPILED_LISTS_EXTENSION = '.cdb'


# ========================================= Cyb3rhq constants - Size and limits ==========================================
MAX_SOCKET_BUFFER_SIZE = 64 * 1024  # 64KB.
MAX_QUERY_FILTERS_RESERVED_SIZE = MAX_SOCKET_BUFFER_SIZE - 4 * 1024  # MAX_BUFFER_SIZE - 4KB.
AGENT_NAME_LEN_LIMIT = 128
DATABASE_LIMIT = 500
MAXIMUM_DATABASE_LIMIT = 100000
MAX_GROUPS_PER_MULTIGROUP = 128


# ============================================= Cyb3rhq constants - Version ==============================================
# Agent upgrading variables.
WPK_REPO_URL_4_X = "packages.wazuh.com/4.x/wpk/"
# Agent component stats required version.
AGENT_COMPONENT_STATS_REQUIRED_VERSION = {'logcollector': 'v4.2.0', 'agent': 'v4.2.0'}
# Version variables (legacy, required, etc).
AR_LEGACY_VERSION = 'Cyb3rhq v4.2.0'
ACTIVE_CONFIG_VERSION = 'Cyb3rhq v3.7.0'


# ================================================ Cyb3rhq path - Config =================================================
OSSEC_CONF = os.path.join(CYB3RHQ_PATH, 'etc', 'ossec.conf')
INTERNAL_OPTIONS_CONF = os.path.join(CYB3RHQ_PATH, 'etc', 'internal_options.conf')
LOCAL_INTERNAL_OPTIONS_CONF = os.path.join(CYB3RHQ_PATH, 'etc', 'local_internal_options.conf')
AR_CONF = os.path.join(CYB3RHQ_PATH, 'etc', 'shared', 'ar.conf')
CLIENT_KEYS = os.path.join(CYB3RHQ_PATH, 'etc', 'client.keys')
SHARED_PATH = os.path.join(CYB3RHQ_PATH, 'etc', 'shared')


# ================================================= Cyb3rhq path - Misc ==================================================
CYB3RHQ_LOGS = os.path.join(CYB3RHQ_PATH, 'logs')
CYB3RHQ_LOG = os.path.join(CYB3RHQ_LOGS, 'ossec.log')
CYB3RHQ_LOG_JSON = os.path.join(CYB3RHQ_LOGS, 'ossec.json')
DATABASE_PATH = os.path.join(CYB3RHQ_PATH, 'var', 'db')
DATABASE_PATH_GLOBAL = os.path.join(DATABASE_PATH, 'global.db')
ANALYSISD_STATS = os.path.join(CYB3RHQ_PATH, 'var', 'run', 'cyb3rhq-analysisd.state')
REMOTED_STATS = os.path.join(CYB3RHQ_PATH, 'var', 'run', 'cyb3rhq-remoted.state')
OSSEC_TMP_PATH = os.path.join(CYB3RHQ_PATH, 'tmp')
OSSEC_PIDFILE_PATH = os.path.join(CYB3RHQ_PATH, 'var', 'run')
OS_PIDFILE_PATH = os.path.join('var', 'run')
WDB_PATH = os.path.join(CYB3RHQ_PATH, 'queue', 'db')
STATS_PATH = os.path.join(CYB3RHQ_PATH, 'stats')
BACKUP_PATH = os.path.join(CYB3RHQ_PATH, 'backup')
MULTI_GROUPS_PATH = os.path.join(CYB3RHQ_PATH, 'var', 'multigroups')
DEFAULT_RBAC_RESOURCES = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'rbac', 'default')


# ================================================ Cyb3rhq path - Sockets ================================================
ANALYSISD_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'sockets', 'analysis')
AR_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'alerts', 'ar')
EXECQ_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'alerts', 'execq')
AUTHD_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'sockets', 'auth')
WCOM_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'sockets', 'com')
LOGTEST_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'sockets', 'logtest')
UPGRADE_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'tasks', 'upgrade')
REMOTED_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'sockets', 'remote')
TASKS_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'tasks', 'task')
WDB_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'db', 'wdb')
WMODULES_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'sockets', 'wmodules')
QUEUE_SOCKET = os.path.join(CYB3RHQ_PATH, 'queue', 'sockets', 'queue')


# ================================================ Cyb3rhq path - Ruleset ================================================
RULESET_PATH = os.path.join(CYB3RHQ_PATH, 'ruleset')
RULES_PATH = os.path.join(RULESET_PATH, 'rules')
DECODERS_PATH = os.path.join(RULESET_PATH, 'decoders')
LISTS_PATH = os.path.join(RULESET_PATH, 'lists')
USER_LISTS_PATH = os.path.join(CYB3RHQ_PATH, 'etc', 'lists')
USER_RULES_PATH = os.path.join(CYB3RHQ_PATH, 'etc', 'rules')
USER_DECODERS_PATH = os.path.join(CYB3RHQ_PATH, 'etc', 'decoders')
