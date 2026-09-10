from typing import Protocol, runtime_checkable

from sastsimi.contracts.ids import OpaqueId


@runtime_checkable
class IdGenerator(Protocol):
    """Trusted IDs only; external commit/program IDs retain their own owners."""

    def new[T: OpaqueId](self, kind: type[T]) -> T: ...
