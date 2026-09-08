"""Explicit startup recovery before workflow execution."""

from sastsimi.ports.runtime_store import RecoveryPort, RecoveryReport


class RecoveryService:
    def __init__(self, recovery: RecoveryPort) -> None:
        self.recovery = recovery

    def recover(self) -> RecoveryReport:
        return self.recovery.recover()
