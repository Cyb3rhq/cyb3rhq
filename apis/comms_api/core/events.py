from cyb3rhq.core.indexer import get_indexer_client
from cyb3rhq.core.indexer.models.events import Events


async def create_stateful_events(events: Events) -> dict:
    """Post new events to the indexer.
    
    Parameters
    ----------
    events : Events
        List of events.
    
    Returns
    -------
    dict
        Dictionary with the indexer response.
    """
    async with get_indexer_client() as indexer_client:
        return await indexer_client.events.create(events)
