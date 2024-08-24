import os

from cyb3rhq.core.exception import Cyb3rhqCommsAPIError

# TODO(#25121): get actual directory path or take ir from the configuration
DIR = '/files'


def get_file_path(file_name: str) -> str:
    """Validates the file name and returns the final path to the file.

    Parameters
    ----------
    file_name : str
        File name.
    
    Raises
    ------
    Cyb3rhqCommsAPIError
        If the path does not comply with the requirements.
    
    Returns
    -------
    str
        Path to the file.    
    """
    if file_name.endswith('/'):
        raise Cyb3rhqCommsAPIError(2704)

    if '/' in file_name:
        raise Cyb3rhqCommsAPIError(2705)

    return os.path.join(DIR, file_name)
