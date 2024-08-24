# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock, call
from asyncio import BaseEventLoop, BaseProtocol, StreamWriter, StreamReader, BaseTransport
from struct import pack

import pytest
from cyb3rhq.core.exception import Cyb3rhqException
from cyb3rhq.core.cyb3rhq_socket import Cyb3rhqSocket, Cyb3rhqSocketJSON, \
     SOCKET_COMMUNICATION_PROTOCOL_VERSION, create_cyb3rhq_socket_message, Cyb3rhqAsyncSocket, \
     Cyb3rhqAsyncSocketJSON

@pytest.fixture
def aux_conn_patch():
    """Fixture with asyncio.open_unix_connection patched."""
    return patch('asyncio.open_unix_connection',
                 return_value=(StreamReader(),StreamWriter(protocol=BaseProtocol(),
                                                           transport=BaseTransport(),
                                                           loop=BaseEventLoop(),
                                                           reader=None)))


@pytest.mark.asyncio
@pytest.fixture
async def connected_cyb3rhq_async_socket(aux_conn_patch):
    """Fixture to instantiate Cyb3rhqAsyncSocket."""
    with aux_conn_patch:
        s = Cyb3rhqAsyncSocket()
        await s.connect('/any/pipe')
        yield s


@patch('cyb3rhq.core.cyb3rhq_socket.Cyb3rhqSocket._connect')
def test_Cyb3rhqSocket__init__(mock_conn):
    """Tests Cyb3rhqSocket.__init__ function works"""

    Cyb3rhqSocket('test_path')

    mock_conn.assert_called_once_with()


@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
def test_Cyb3rhqSocket_protected_connect(mock_conn):
    """Tests Cyb3rhqSocket._connect function works"""

    Cyb3rhqSocket('test_path')

    mock_conn.assert_called_with('test_path')


@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect', side_effect=Exception)
def test_Cyb3rhqSocket_protected_connect_ko(mock_conn):
    """Tests Cyb3rhqSocket._connect function exceptions works"""

    with pytest.raises(Cyb3rhqException, match=".* 1013 .*"):
        Cyb3rhqSocket('test_path')


@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.close')
def test_Cyb3rhqSocket_close(mock_close, mock_conn):
    """Tests Cyb3rhqSocket.close function works"""

    queue = Cyb3rhqSocket('test_path')

    queue.close()

    mock_conn.assert_called_once_with('test_path')
    mock_close.assert_called_once_with()


@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.send')
def test_Cyb3rhqSocket_send(mock_send, mock_conn):
    """Tests Cyb3rhqSocket.send function works"""

    queue = Cyb3rhqSocket('test_path')

    response = queue.send(b"\x00\x01")

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('msg, effect, send_effect, expected_exception', [
    ('text_msg', 'side_effect', None, 1105),
    (b"\x00\x01", 'return_value', 0, 1014),
    (b"\x00\x01", 'side_effect', Exception, 1014)
])
@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
def test_Cyb3rhqSocket_send_ko(mock_conn, msg, effect, send_effect, expected_exception):
    """Tests Cyb3rhqSocket.send function exceptions works"""

    queue = Cyb3rhqSocket('test_path')

    if effect == 'return_value':
        with patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.send', return_value=send_effect):
            with pytest.raises(Cyb3rhqException, match=f'.* {expected_exception} .*'):
                queue.send(msg)
    else:
        with patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.send', side_effect=send_effect):
            with pytest.raises(Cyb3rhqException, match=f'.* {expected_exception} .*'):
                queue.send(msg)

    mock_conn.assert_called_once_with('test_path')


@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
@patch('cyb3rhq.core.cyb3rhq_socket.unpack', return_value='1024')
@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.recv')
def test_Cyb3rhqSocket_receive(mock_recv, mock_unpack, mock_conn):
    """Tests Cyb3rhqSocket.receive function works"""

    queue = Cyb3rhqSocket('test_path')

    response = queue.receive()

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.recv', side_effect=Exception)
def test_Cyb3rhqSocket_receive_ko(mock_recv, mock_conn):
    """Tests Cyb3rhqSocket.receive function exception works"""

    queue = Cyb3rhqSocket('test_path')

    with pytest.raises(Cyb3rhqException, match=".* 1014 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@patch('cyb3rhq.core.cyb3rhq_socket.Cyb3rhqSocket._connect')
def test_Cyb3rhqSocketJSON__init__(mock_conn):
    """Tests Cyb3rhqSocketJSON.__init__ function works"""

    Cyb3rhqSocketJSON('test_path')

    mock_conn.assert_called_once_with()


@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
@patch('cyb3rhq.core.cyb3rhq_socket.Cyb3rhqSocket.send')
def test_Cyb3rhqSocketJSON_send(mock_send, mock_conn):
    """Tests Cyb3rhqSocketJSON.send function works"""

    queue = Cyb3rhqSocketJSON('test_path')

    response = queue.send('test_msg')

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('raw', [
    True, False
])
@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
@patch('cyb3rhq.core.cyb3rhq_socket.Cyb3rhqSocket.receive')
@patch('cyb3rhq.core.cyb3rhq_socket.loads', return_value={'error':0, 'message':None, 'data':'Ok'})
def test_Cyb3rhqSocketJSON_receive(mock_loads, mock_receive, mock_conn, raw):
    """Tests Cyb3rhqSocketJSON.receive function works"""
    queue = Cyb3rhqSocketJSON('test_path')
    response = queue.receive(raw=raw)
    if raw:
        assert isinstance(response, dict)
    else:
        assert isinstance(response, str)
    mock_conn.assert_called_once_with('test_path')


@patch('cyb3rhq.core.cyb3rhq_socket.socket.socket.connect')
@patch('cyb3rhq.core.cyb3rhq_socket.Cyb3rhqSocket.receive')
@patch('cyb3rhq.core.cyb3rhq_socket.loads', return_value={'error':10000, 'message':'Error', 'data':'KO'})
def test_Cyb3rhqSocketJSON_receive_ko(mock_loads, mock_receive, mock_conn):
    """Tests Cyb3rhqSocketJSON.receive function works"""

    queue = Cyb3rhqSocketJSON('test_path')

    with pytest.raises(Cyb3rhqException, match=".* 10000 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('origin, command, parameters', [
    ('origin_sample', 'command_sample', {'sample': 'sample'}),
    (None, 'command_sample', {'sample': 'sample'}),
    ('origin_sample', None, {'sample': 'sample'}),
    ('origin_sample', 'command_sample', None),
    (None, None, None)
])
def test_create_cyb3rhq_socket_message(origin, command, parameters):
    """Test create_cyb3rhq_socket_message function."""
    response_message = create_cyb3rhq_socket_message(origin, command, parameters)
    assert response_message['version'] == SOCKET_COMMUNICATION_PROTOCOL_VERSION
    assert response_message.get('origin') == origin
    assert response_message.get('command') == command
    assert response_message.get('parameters') == parameters


@pytest.mark.asyncio
async def test_cyb3rhq_async_socket_connect():
    """Test socket connection."""
    s = Cyb3rhqAsyncSocket()
    with patch('asyncio.open_unix_connection',
               return_value=(StreamReader(),
                             StreamWriter(protocol=BaseProtocol(),
                                          transport=BaseTransport(),
                                          loop=BaseEventLoop(),
                                          reader=StreamReader()))) as mock_open:
        await s.connect(path_to_socket='/etc/socket/path')
        assert isinstance(s.reader, StreamReader, )
        assert isinstance(s.writer, StreamWriter)
        mock_open.assert_awaited_once_with('/etc/socket/path')


@pytest.mark.parametrize('exception', [(ValueError()),(OSError),(FileNotFoundError),((AttributeError()))])
async def test_cyb3rhq_async_socket_connect_ko(exception):
    """Test socket connection errors."""
    s = Cyb3rhqAsyncSocket()
    aux_conn_patch.side_effect = exception
    with patch('asyncio.open_unix_connection', side_effect=exception):
        with pytest.raises(Cyb3rhqException) as exc_info:
            await s.connect(path_to_socket='/etc/socket/path')

    assert exc_info.value.code == 1013
    assert exc_info.errisinstance(Cyb3rhqException)


@pytest.mark.asyncio
async def test_cyb3rhq_async_socket_receive(connected_cyb3rhq_async_socket: Cyb3rhqAsyncSocket):
    """Test receive function."""
    with patch.object(connected_cyb3rhq_async_socket.reader, 'read',
                      side_effect=[b'\x05\x00\x00\x00', b'12345']) as read_patch:
        data = await connected_cyb3rhq_async_socket.receive()
        assert data == b'12345'
        read_patch.assert_has_awaits([call(4), call(5)])


@pytest.mark.asyncio
async def test_cyb3rhq_async_socket_receive_ko(connected_cyb3rhq_async_socket: Cyb3rhqAsyncSocket):
    """Test receive function."""
    with patch.object(connected_cyb3rhq_async_socket.reader, 'read',
                      side_effect=Exception()):
        with pytest.raises(Cyb3rhqException) as exc_info:
            await connected_cyb3rhq_async_socket.receive()
    assert exc_info.value.code == 1014
    assert exc_info.errisinstance(Cyb3rhqException)


@pytest.mark.asyncio
async def test_cyb3rhq_async_socket_send(connected_cyb3rhq_async_socket: Cyb3rhqAsyncSocket):
    """Test receive function."""
    d_bytes = b'12345'
    with patch.object(connected_cyb3rhq_async_socket.writer, 'write') as write_patch,\
         patch.object(connected_cyb3rhq_async_socket.writer, 'drain') as drain_patch:
        await connected_cyb3rhq_async_socket.send(d_bytes)
        bytes_sent = pack('<I', len(d_bytes)) + d_bytes
        write_patch.assert_called_once_with(bytes_sent)
        drain_patch.assert_awaited_once()


@pytest.mark.asyncio
async def test_cyb3rhq_async_socket_send_ko(connected_cyb3rhq_async_socket: Cyb3rhqAsyncSocket):
    """Test receive function."""
    with patch.object(connected_cyb3rhq_async_socket.writer, 'write',
                      side_effect=OSError()):
        with pytest.raises(Cyb3rhqException) as exc_info:
            await connected_cyb3rhq_async_socket.send(b'12345')
    assert exc_info.value.code == 1014
    assert exc_info.errisinstance(Cyb3rhqException)


def test_cyb3rhq_async_socket_close(connected_cyb3rhq_async_socket: Cyb3rhqAsyncSocket):
    """Test receive function."""

    with patch.object(connected_cyb3rhq_async_socket.writer, 'close') as close_patch:
        connected_cyb3rhq_async_socket.close()
        close_patch.assert_called_once()


@pytest.mark.asyncio
async def test_cyb3rhq_async_json_socket_receive_json():
    """Test receive_json function."""

    s = Cyb3rhqAsyncSocketJSON()
    with patch.object(Cyb3rhqAsyncSocket,
                      'receive', return_value=b'{"data": {"field":"value"}}') as receive_patch:
        msg = await s.receive_json()
        receive_patch.assert_called_once()
        assert msg['field'] == 'value'


@pytest.mark.asyncio
async def test_cyb3rhq_async_json_socket_receive_json_ko():
    """Test receive_json function."""

    s = Cyb3rhqAsyncSocketJSON()
    with patch.object(Cyb3rhqAsyncSocket, 'receive',
                      return_value=b'{"error": 1000, "message": "error message"}'):
        with pytest.raises(Cyb3rhqException) as exc_info:
            await s.receive_json()
        exc_info.errisinstance(Cyb3rhqException)
        assert exc_info.value.code == 1000
