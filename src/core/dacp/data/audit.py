'''
Lightweight JSON audit log for local DACP dataset experiments.
'''

import json
from datetime import datetime


class AuditLog:
    def __init__(self):
        self.events = []

    def add_event(self, event_type, **kwargs):
        event = {
            'event_type': event_type,
            'timestamp': datetime.utcnow().replace(microsecond=0).isoformat() + 'Z',
        }
        event.update(kwargs)
        self.events.append(event)
        return event

    def to_list(self):
        return list(self.events)

    def save_json(self, path):
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(self.events, handle, sort_keys=True, indent=2)
            handle.write('\n')
