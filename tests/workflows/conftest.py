"""
Pytest fixtures for workflow integration tests.

These tests need a database with real functions to analyze.
We use tiny_c.bin which has multiple functions for workflow testing.
"""

import os
import tempfile

import pytest

import ida_domain
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def workflow_test_setup():
    """Setup for workflow tests - prepares tiny_c.bin database."""
    work_dir = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir')
    idb_path = os.path.join(work_dir, 'tiny_c.bin')

    # Ensure database exists (created by session fixture in main conftest.py)
    i64_path = idb_path + '.i64'
    if not os.path.exists(i64_path):
        # Fallback: copy and create if needed
        import shutil
        current_dir = os.path.dirname(os.path.abspath(__file__))
        src_path = os.path.join(current_dir, '..', 'resources', 'tiny_c.bin')
        os.makedirs(work_dir, exist_ok=True)
        if not os.path.exists(idb_path):
            shutil.copy2(src_path, idb_path)

    yield idb_path


@pytest.fixture(scope='function')
def test_env(workflow_test_setup):
    """Opens tiny_c database for each workflow test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(
        path=workflow_test_setup,
        args=ida_options,
        save_on_close=False
    )
    yield db
    db.close()
