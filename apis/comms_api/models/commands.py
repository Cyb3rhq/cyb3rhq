from typing import List

from pydantic import BaseModel

from cyb3rhq.core.indexer.models.commands import Command


class Commands(BaseModel):
    commands: List[Command]
