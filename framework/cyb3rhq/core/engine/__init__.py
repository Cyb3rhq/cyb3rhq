from contextlib import asynccontextmanager
from logging import getLogger
from typing import AsyncIterator

from httpx import AsyncClient, AsyncHTTPTransport, ConnectError, Timeout, TimeoutException, UnsupportedProtocol
from cyb3rhq.core.exception import Cyb3rhqEngineError

logger = getLogger('cyb3rhq')

# TODO: use actual default path
ENGINE_API_SOCKET_PATH = '/var/cyb3rhq/queue/engine.sock'
DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 0.5


class Engine:
    """Cyb3rhq Engine API client."""

    def __init__(
        self,
        socket_path: str = ENGINE_API_SOCKET_PATH,
        retries: int = DEFAULT_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        transport = AsyncHTTPTransport(uds=socket_path, retries=retries)
        self._client = AsyncClient(transport=transport, timeout=Timeout(timeout))

        # Register Engine modules here

    async def close(self) -> None:
        """Close the Engine client."""
        await self._client.aclose()


@asynccontextmanager
async def get_engine_client() -> AsyncIterator[Engine]:
    """Create and return the engine client.

    Returns
    -------
    AsyncIterator[Engine]
        Engine client iterator.
    """
    # TODO: get class parameters from the configuration
    client = Engine()

    try:
        yield client
    except TimeoutException:
        raise Cyb3rhqEngineError(2800)
    except UnsupportedProtocol:
        raise Cyb3rhqEngineError(2801)
    except ConnectError:
        raise Cyb3rhqEngineError(2802)
    finally:
        await client.close()
