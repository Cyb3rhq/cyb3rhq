from pathlib import Path

import pytest

from comms_api.core.files import DIR, get_file_path
from cyb3rhq.core.exception import Cyb3rhqCommsAPIError


def test_get_file_path():
    """Verify the `get_file_path` function is working as expected."""
    file_name = 'test.txt'
    expected_path = f'{DIR}/{file_name}'
    path = get_file_path(file_name)

    assert path == expected_path


@pytest.mark.parametrize('file_name,exception,error_code', [
    ('test/', Cyb3rhqCommsAPIError, 2704),
    ('dir/test.txt', Cyb3rhqCommsAPIError, 2705),
])
def test_get_file_path_ko(file_name, exception, error_code) -> None:
    """Assert exceptions are handled as expected inside the `get_file_path` function."""
    with pytest.raises(exception, match=f'.*{error_code}.*'):
        _ = get_file_path(file_name)
