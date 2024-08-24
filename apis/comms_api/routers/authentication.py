from fastapi import status

from comms_api.authentication.authentication import generate_token
from comms_api.models.authentication import Credentials, TokenResponse
from comms_api.routers.exceptions import HTTPError
from comms_api.routers.utils import timeout
from cyb3rhq.core.exception import Cyb3rhqInternalError, Cyb3rhqIndexerError, Cyb3rhqResourceNotFound
from cyb3rhq.core.indexer import get_indexer_client
from cyb3rhq.core.indexer.models.agent import Agent
from cyb3rhq.core.utils import get_utc_now


@timeout(20)
async def authentication(credentials: Credentials) -> TokenResponse:
    """Authentication endpoint handler.

    Parameters
    ----------
    credentials : Credentials
        Agent credentials.

    Raises
    ------
    HTTPError
        If there is an error during the authentication.

    Returns
    -------
    TokenResponse
        JWT token.
    """
    try:
        async with get_indexer_client() as indexer_client:
            agent = await indexer_client.agents.get(credentials.uuid)

            if not agent.check_key(credentials.key):
                raise HTTPError(message='Invalid key', status_code=status.HTTP_401_UNAUTHORIZED)

            token = generate_token(credentials.uuid)

            body = Agent(last_login=get_utc_now())
            await indexer_client.agents.update(credentials.uuid, body)
    except Cyb3rhqIndexerError as exc:
        raise HTTPError(message=f'Couldn\'t connect to the indexer: {str(exc)}', status_code=status.HTTP_403_FORBIDDEN)
    except Cyb3rhqResourceNotFound:
        raise HTTPError(message='Agent does not exist', status_code=status.HTTP_403_FORBIDDEN)
    except Cyb3rhqInternalError as exc:
        raise HTTPError(message=f'Couldn\'t get key pair: {str(exc)}', status_code=status.HTTP_403_FORBIDDEN)

    return TokenResponse(token=token)
