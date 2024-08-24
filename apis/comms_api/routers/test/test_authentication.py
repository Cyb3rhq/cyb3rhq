from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from freezegun import freeze_time

from comms_api.models.authentication import Credentials, TokenResponse
from comms_api.routers.authentication import authentication
from comms_api.routers.exceptions import HTTPError
from cyb3rhq.core.exception import Cyb3rhqInternalError, Cyb3rhqIndexerError, Cyb3rhqResourceNotFound
from cyb3rhq.core.indexer.models.agent import Agent
from cyb3rhq.core.utils import get_utc_now


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1))
@patch('cyb3rhq.core.indexer.Indexer._get_opensearch_client', new_callable=AsyncMock)
@patch('cyb3rhq.core.indexer.Indexer.connect')
@patch('cyb3rhq.core.indexer.Indexer.close')
@patch('cyb3rhq.core.indexer.agent.AgentsIndex.get')
@patch('cyb3rhq.core.indexer.agent.AgentsIndex.update')
@patch('comms_api.routers.authentication.generate_token', return_value='token')
async def test_authentication(
    generate_token_mock,
    agents_index_update_mock,
    agents_index_get_mock,
    close_mock,
    connect_mock,
    get_opensearch_client_mock,
):
    """Verify that the `authentication` handler works as expected."""
    uuid = '0'
    credentials = Credentials(uuid=uuid, key='key')
    response = await authentication(credentials)
    
    get_opensearch_client_mock.assert_called_once()
    connect_mock.assert_called_once()
    close_mock.assert_called_once()
    agents_index_get_mock.assert_called_once_with(uuid)
    agents_index_update_mock.assert_called_once_with(uuid, Agent(last_login=get_utc_now()))
    generate_token_mock.assert_called_once_with(credentials.uuid)
    assert response == TokenResponse(token='token')

@pytest.mark.asyncio
@pytest.mark.parametrize('exception,message', [
    (Cyb3rhqIndexerError(2200), 'Couldn\'t connect to the indexer: Error 2200 - Could not connect to the indexer'),
    (Cyb3rhqResourceNotFound(1701), 'Agent does not exist'),
    (Cyb3rhqInternalError(6003), 'Couldn\'t get key pair: Error 6003 - Error trying to load the JWT secret'),
])
async def test_authentication_ko(exception, message):
    """Verify that the `authentication` handler catches exceptions successfully."""
    with patch('cyb3rhq.core.indexer.create_indexer', AsyncMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=fr'{status.HTTP_403_FORBIDDEN}: {message}'):
            _ = await authentication(Credentials(uuid='', key=''))
