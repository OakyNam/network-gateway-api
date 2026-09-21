"""Read-only transaction (audit) query use cases; no mutation methods exist here."""

from app.bl.services.management import store_call


class TransactionsService:
    def __init__(self, store):
        self.store = store

    def list(self, *, connection_id=None, action=None, actor_subject=None, outcome=None,
             from_time=None, to_time=None, limit=50, offset=0):
        filters = {
            "connection_id": connection_id,
            "action": action,
            "actor_subject": actor_subject,
            "outcome": outcome,
            "since": from_time,
            "until": to_time,
        }
        return store_call(
            self.store, "list_transactions",
            filters={key: value for key, value in filters.items() if value is not None},
            limit=limit, offset=offset,
        )