from fastapi import APIRouter, Depends, status
from fastapi.responses import Response

from comms_api.authentication.authentication import JWTBearer
from comms_api.routers.authentication import authentication
from comms_api.routers.commands import get_commands
from comms_api.routers.events import post_stateful_events
from comms_api.routers.files import get_files

router = APIRouter(prefix='/api/v1')
router.add_api_route('/authentication', authentication, methods=['POST'])
router.add_api_route('/commands', get_commands, methods=['GET'])
router.add_api_route('/events/stateful', post_stateful_events, dependencies=[Depends(JWTBearer())], methods=['POST'])
router.add_api_route('/files', get_files, methods=['GET'], dependencies=[Depends(JWTBearer())])


@router.get('/')
async def home():
    return Response(status_code=status.HTTP_200_OK)
