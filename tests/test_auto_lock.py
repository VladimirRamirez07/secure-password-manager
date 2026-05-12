"""
Tests for the auto-lock module.
"""

import time
import pytest
from src.utils.auto_lock import AutoLock


@pytest.fixture
def lock():
    al = AutoLock(timeout=2)  # 2 seconds for fast tests
    yield al
    al.stop()


class TestAutoLock:

    def test_initial_state_not_expired(self, lock):
        assert lock.is_expired is False

    def test_time_remaining_is_positive(self, lock):
        assert lock.time_remaining > 0

    def test_reset_resets_timer(self, lock):
        time.sleep(1)
        lock.reset()
        assert lock.time_remaining >= 1

    def test_expires_after_timeout(self, lock):
        time.sleep(2.1)
        assert lock.is_expired is True

    def test_callback_called_on_expiry(self, lock):
        called = []
        lock.start(lambda: called.append(True))
        time.sleep(15)  # wait for the 10s check interval + 2s timeout
        assert len(called) > 0

    def test_set_timeout_updates_value(self, lock):
        lock.set_timeout(60)
        assert lock.timeout == 60

    def test_set_timeout_too_short_raises(self, lock):
        with pytest.raises(ValueError):
            lock.set_timeout(10)

    def test_stop_prevents_callback(self):
        called = []
        al = AutoLock(timeout=1)
        al.start(lambda: called.append(True))
        al.stop()
        time.sleep(2)
        assert len(called) == 0