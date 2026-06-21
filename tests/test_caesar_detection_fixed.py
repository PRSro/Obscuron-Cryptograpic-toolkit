#!/usr/bin/env python3
"""
Focused test for Caesar cipher detection.
"""

import subprocess
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def ob_run(*args):
    """
    Minimal wrapper around subprocess.run that mimics the test harness.
    """
    cmd = [os.path.join(PROJECT_ROOT, "CLI", "ob-crypt")] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def test_detect_caesar_shift3():
    """Caesar shift 3 should be detected as 'caesar'."""
    # Encrypt with Caesar cipher
    ct = ob_run("caesar", "-k", "3", "The quick brown fox jumps over the lazy dog")[1].strip()
    # Detect the cipher type
    rc, out, err = ob_run("detect", ct)
    assert rc == 0, err
    # Verify that 'caesar' appears in the detection output
    assert "caesar" in out, f"Expected 'caesar' in output, got: {out}"

if __name__ == "__main__":
    test_detect_caesar_shift3()
    print("Test passed!")