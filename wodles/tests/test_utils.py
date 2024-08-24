import os
import pytest
import subprocess
import sys
from unittest.mock import Mock, patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
from utils import find_cyb3rhq_path, call_cyb3rhq_control, get_cyb3rhq_info, get_cyb3rhq_version


@pytest.mark.parametrize('path, expected', [
    ('/var/ossec/wodles/aws', '/var/ossec'),
    ('/my/custom/path/wodles/aws', '/my/custom/path'),
    ('/my/fake/path', '')
])
def test_find_cyb3rhq_path(path, expected):
    """Validate that the Cyb3rhq absolute path is returned successfully."""
    with patch('utils.__file__', new=path):
        assert (find_cyb3rhq_path.__wrapped__() == expected)


def test_find_cyb3rhq_path_relative_path():
    """Validate that the Cyb3rhq relative path is returned successfully."""
    with patch('os.path.abspath', return_value='~/wodles'):
        assert (find_cyb3rhq_path.__wrapped__() == '~')


@patch("subprocess.Popen")
@pytest.mark.parametrize('option', ['info', 'status'])
def test_call_cyb3rhq_control(mock_popen, option):
    """Validate that the call_cyb3rhq_control function works correctly."""
    b_output = b'output'
    process_mock = Mock()
    attrs = {'communicate.return_value': (b_output, b'error')}
    process_mock.configure_mock(**attrs)
    mock_popen.return_value = process_mock

    output = call_cyb3rhq_control(option)
    assert output == b_output.decode()
    mock_popen.assert_called_once_with([os.path.join(find_cyb3rhq_path(), "bin", "cyb3rhq-control"), option], 
                                               stdout=subprocess.PIPE)


def test_call_cyb3rhq_control_ko():
    """Validate that call_cyb3rhq_control exists with a code 1 when there's a system error."""
    with pytest.raises(SystemExit) as sys_exit:
        with patch('subprocess.Popen', side_effect=OSError):
            call_cyb3rhq_control('info')

    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 1


@pytest.mark.parametrize('field, cyb3rhq_info, expected', [
    ('CYB3RHQ_VERSION', 'CYB3RHQ_VERSION="v5.0.0"\nCYB3RHQ_REVISION="50000"\nCYB3RHQ_TYPE="server"\n', 'v5.0.0'),
    ('CYB3RHQ_REVISION', 'CYB3RHQ_VERSION="v5.0.0"\nCYB3RHQ_REVISION="50000"\nCYB3RHQ_TYPE="server"\n', '50000'),
    ('CYB3RHQ_TYPE', 'CYB3RHQ_VERSION="v5.0.0"\nCYB3RHQ_REVISION="50000"\nCYB3RHQ_TYPE="server"\n', 'server'),
    (None, 'CYB3RHQ_REVISION="50000"', 'CYB3RHQ_REVISION="50000"'),
    ('CYB3RHQ_TYPE', None, 'ERROR')
])
def test_get_cyb3rhq_info(field, cyb3rhq_info, expected):
    """Validate that get_cyb3rhq_info returns the correct information."""
    with patch('utils.call_cyb3rhq_control', return_value=cyb3rhq_info):
        actual = get_cyb3rhq_info(field)
        assert actual == expected


def test_get_cyb3rhq_version():
    """Validate that get_cyb3rhq_version returns the correct information."""
    cyb3rhq_info = 'CYB3RHQ_VERSION="v5.0.0"\nCYB3RHQ_REVISION="50000"\nCYB3RHQ_TYPE="server"\n'
    expected = 'v5.0.0'
    with patch('utils.call_cyb3rhq_control', return_value=cyb3rhq_info):
        version = get_cyb3rhq_version()

    assert version == expected
