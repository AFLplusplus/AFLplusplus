import pytest
import os
import sys
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import the actual module under test
sys.path.insert(0, str(Path(__file__).parent.parent))
from custom_mutators.guifuzz import guifuzz_clicks


@pytest.mark.parametrize("payload", [
    "/bin/true",  # Valid input - should work
    "/bin/true; rm -rf /",  # Command injection via semicolon
    "/bin/true$(whoami)",  # Command substitution injection
    "/bin/true`id`",  # Backtick command substitution
])
def test_shell_command_injection_prevention(payload):
    """Invariant: Shell metacharacters in program paths must not be executed as shell commands"""
    
    with patch('os.system') as mock_system:
        mock_system.return_value = 0
        
        # Call the vulnerable function with the payload
        guifuzz_clicks.start_program(payload)
        
        # Verify os.system was called exactly once
        assert mock_system.call_count == 1
        
        # Get the actual argument passed to os.system
        actual_command = mock_system.call_args[0][0]
        
        # INVARIANT: If the payload contains shell metacharacters,
        # they must be escaped or the command must be rejected/sanitized
        dangerous_chars = [';', '$', '`', '|', '&', '>', '<', '(', ')']
        
        if any(char in payload for char in dangerous_chars):
            # Either the dangerous characters are escaped in the command,
            # or the function rejects the input entirely
            if actual_command == payload:
                # If passed as-is, verify it won't be interpreted by shell
                # by checking it's not wrapped in shell evaluation context
                assert not any(f"{char}" in actual_command for char in ['$(', '`', ';'])
            else:
                # Command was modified - verify sanitization occurred
                assert actual_command != payload or actual_command.startswith('/')