import subprocess
import tempfile
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OB_CRYPT = os.path.join(PROJECT_ROOT, "CLI", "ob-crypt")


def ob_run(*args, input_data=None):
    """Run ob-crypt with args, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [OB_CRYPT] + list(args),
        input=input_data.encode() if input_data else None,
        capture_output=True,
        timeout=30,
    )
    return result.returncode, result.stdout.decode(), result.stderr.decode()
