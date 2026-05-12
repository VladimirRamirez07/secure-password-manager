"""
Auto-lock module.
Locks the vault automatically after a period of inactivity.

Why auto-lock matters:
- Prevents unauthorized access if the user walks away
- Clears the session key from memory after timeout
- Threat mitigated: physical access to an unlocked session
"""

import time
import threading


class AutoLock:

    DEFAULT_TIMEOUT = 300   # 5 minutes in seconds

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self._last_activity = time.time()
        self._lock_callback = None
        self._timer: threading.Timer | None = None
        self._running = False

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def start(self, lock_callback) -> None:
        """
        Starts the auto-lock timer.
        lock_callback: function to call when vault should be locked.
        """
        self._lock_callback = lock_callback
        self._running = True
        self._schedule_check()

    def stop(self) -> None:
        """Stops the auto-lock timer (call on app exit or manual lock)."""
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def reset(self) -> None:
        """Resets the inactivity timer (call on every user action)."""
        self._last_activity = time.time()

    def set_timeout(self, seconds: int) -> None:
        """Updates the inactivity timeout."""
        if seconds < 30:
            raise ValueError("Timeout must be at least 30 seconds")
        self.timeout = seconds
        self.reset()

    @property
    def time_remaining(self) -> int:
        """Returns seconds until auto-lock triggers."""
        elapsed = time.time() - self._last_activity
        remaining = self.timeout - elapsed
        return max(0, int(remaining))

    @property
    def is_expired(self) -> bool:
        """Returns True if the session has timed out."""
        return (time.time() - self._last_activity) >= self.timeout

    # ------------------------------------------------------------------ #
    #  Internal timer logic                                                #
    # ------------------------------------------------------------------ #

    def _schedule_check(self) -> None:
        """Schedules the next inactivity check (every 10 seconds)."""
        if not self._running:
            return

        self._timer = threading.Timer(10, self._check_inactivity)
        self._timer.daemon = True   # Dies with the main thread
        self._timer.start()

    def _check_inactivity(self) -> None:
        """Checks if the vault should be locked due to inactivity."""
        if not self._running:
            return

        if self.is_expired:
            if self._lock_callback:
                self._lock_callback()
            self.stop()
        else:
            self._schedule_check()