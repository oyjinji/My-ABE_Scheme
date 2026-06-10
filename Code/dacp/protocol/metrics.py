'''
Protocol-level metrics for DACP local simulation.
'''

import time


class ProtocolMetrics:
    def __init__(self):
        self.counters = {}
        self.timers = {}
        self._starts = {}

    def start_timer(self, name):
        self._starts[name] = time.time()

    def stop_timer(self, name):
        start = self._starts.pop(name, None)
        if start is None:
            return 0.0
        elapsed = time.time() - start
        self.timers[name] = self.timers.get(name, 0.0) + elapsed
        return elapsed

    def add_bytes(self, name, n):
        self.increment(name, int(n))
        self.increment('total_protocol_bytes', int(n))

    def increment(self, name, value=1):
        self.counters[name] = self.counters.get(name, 0) + value

    def get(self, name, default=0):
        if name in self.counters:
            return self.counters[name]
        return self.timers.get(name, default)

    def summary(self):
        data = {}
        data.update(self.counters)
        data.update(self.timers)
        for name in (
                'oprf_request_bytes',
                'oprf_response_bytes',
                'tk_provision_bytes',
                'ciphertext_upload_bytes',
                'access_request_bytes',
                'transform_response_bytes',
                'total_protocol_bytes',
                'oprf_request_wire_bytes',
                'oprf_response_wire_bytes',
                'tk_provision_wire_bytes',
                'ciphertext_upload_wire_bytes',
                'access_request_wire_bytes',
                'transform_response_wire_bytes',
                'other_protocol_wire_bytes',
                'wire_total_bytes',
                'wire_num_messages',
                'num_messages',
                'num_tk_provision',
                'num_replayed_messages',
                'num_expired_messages',
                'num_external_oprf_tokens',
                'num_abf_queries',
                'num_matched_candidates'):
            data.setdefault(name, 0)
        for name in (
                'setup_time',
                'user_key_time',
                'oprf_round_time',
                'do_encrypt_time',
                'csp_transform_time',
                'du_final_decrypt_time',
                'end_to_end_time'):
            data.setdefault(name, 0.0)
        return data

    def print_summary(self):
        data = self.summary()
        print('Protocol Metrics')
        print('-' * 72)
        for name in sorted(data.keys()):
            value = data[name]
            if name.endswith('_time') or name.endswith('_round_time'):
                print('{:<30} {:>12.3f} ms'.format(name, value * 1000.0))
            else:
                print('{:<30} {:>12}'.format(name, value))
