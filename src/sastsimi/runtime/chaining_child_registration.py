"""Durable child-handoff requirement for the integration adapter.

The concrete ``ChainingChildHandoffPort`` adapter is intentionally not built
from the generic ``ReadyWorkPort`` here.  It must atomically key registration
by ``(source_result_ref, proposal_id)`` and return the same READY work when
reconciliation repeats the call, without charging budget or creating work a
second time.  The integration composition supplies that durable authority.
"""
