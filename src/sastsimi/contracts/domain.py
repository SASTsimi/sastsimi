"""Public access to shared contract traversal and exact-reference helpers."""

from ._domain import DomainRecord as DomainRecord
from ._domain import SafeDiagnostic as SafeDiagnostic
from ._domain import exact as exact
from ._domain import same_scope as same_scope
from ._domain import unique as unique
from ._domain import walk as walk

__all__ = ["DomainRecord", "SafeDiagnostic", "exact", "same_scope", "unique", "walk"]
