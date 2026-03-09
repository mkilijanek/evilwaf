import io
import json
import tempfile
import threading
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i
from core.record_store import RecordStore


class RecordSpoolTest(unittest.TestCase):
    def test_record_store_basic_flow(self):
        with tempfile.TemporaryDirectory() as d:
            spool_path = f"{d}/store.jsonl"
            store = RecordStore(record_limit=1000, spool_path=spool_path, spool_max_bytes=64)
            r1 = i.ProxyRecord(
                request=i.InterceptedRequest(host="one", method="GET"),
                response=i.InterceptedResponse(status_code=200),
                passed=True,
            )
            r2 = i.ProxyRecord(
                request=i.InterceptedRequest(host="two", method="GET"),
                response=i.InterceptedResponse(status_code=403),
                blocked=True,
            )
            store.append(r1)
            store.append(r2)
            self.assertEqual(len(store.get_records()), 2)
            self.assertEqual(store.get_records()[-1].request.host, "two")
            m = store.get_metrics()
            self.assertEqual(m["total_records"], 2)
            self.assertEqual(m["passed_records"], 1)
            self.assertEqual(m["blocked_records"], 1)
            store.clear()
            self.assertEqual(store.get_records(), [])
            store.close()

    def test_record_store_guard_branches(self):
        store = RecordStore(record_limit=1000, spool_path=None)
        store._rotate_spool_if_needed_unlocked()
        store.spill_record(i.ProxyRecord())
        self.assertEqual(store.get_spooled_records(), [])
        store.close()

        with tempfile.TemporaryDirectory() as d:
            p = f"{d}/x.jsonl"
            store2 = RecordStore(record_limit=1000, spool_path=p)
            with mock.patch.object(i.os.path, "getsize", side_effect=OSError("x")):
                store2._rotate_spool_if_needed_unlocked()
            with open(f"{p}.1.gz", "wb") as _:
                pass
            with mock.patch.object(i.gzip, "open", side_effect=OSError("x")):
                out = store2.get_spooled_records(limit=5)
            self.assertIsInstance(out, list)
            store2.close()
    def test_append_record_spills_oldest_when_buffer_full(self):
        with tempfile.TemporaryDirectory() as d:
            inter = i.Interceptor(record_limit=1000, record_spool_path=f"{d}/records.jsonl")
            inter._records = i.deque(maxlen=1)
            inter._record_store.buffer = inter._records
            old = i.ProxyRecord(
                request=i.InterceptedRequest(timestamp=1.0, method="GET", host="old.example", path="/a"),
                response=i.InterceptedResponse(status_code=200, response_time=0.1),
                technique_applied="x",
                passed=True,
                blocked=False,
            )
            new = i.ProxyRecord(
                request=i.InterceptedRequest(timestamp=2.0, method="POST", host="new.example", path="/b"),
                response=i.InterceptedResponse(status_code=403, response_time=0.2),
                technique_applied="y",
                passed=False,
                blocked=True,
            )
            inter._append_record(old)
            inter._append_record(new)
            self.assertEqual(len(inter._records), 1)
            self.assertEqual(inter._records[0].request.host, "new.example")
            spilled = inter.get_spooled_records(limit=10)
            self.assertTrue(spilled)
            payload = spilled[-1]
            self.assertEqual(payload["host"], "old.example")
            self.assertEqual(payload["status_code"], 200)
            inter.stop()

    def test_spill_and_append_fallback_paths(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._record_spool_fp = None
        inter._record_spool_lock = None
        inter._spill_record(i.ProxyRecord())

        inter._record_spool_fp = io.StringIO()
        inter._record_spool_lock = None
        rec = i.ProxyRecord(
            request=i.InterceptedRequest(timestamp=3.0, method="GET", host="nolock.example", path="/"),
            response=i.InterceptedResponse(status_code=201, response_time=0.05),
            passed=True,
        )
        inter._spill_record(rec)
        self.assertIn("nolock.example", inter._record_spool_fp.getvalue())

        inter2 = i.Interceptor.__new__(i.Interceptor)
        inter2._records = None
        inter2._records_lock = None
        inter2._record_spool_fp = None
        inter2._record_spool_lock = None
        inter2._append_record(i.ProxyRecord())

        inter3 = i.Interceptor.__new__(i.Interceptor)
        inter3._records = i.deque(maxlen=1)
        inter3._records_lock = None
        inter3._record_spool_fp = io.StringIO()
        inter3._record_spool_lock = None
        inter3._append_record(
            i.ProxyRecord(
                request=i.InterceptedRequest(timestamp=4.0, method="GET", host="first.example"),
                response=i.InterceptedResponse(status_code=202),
            )
        )
        inter3._append_record(
            i.ProxyRecord(
                request=i.InterceptedRequest(timestamp=5.0, method="GET", host="second.example"),
                response=i.InterceptedResponse(status_code=203),
            )
        )
        self.assertEqual(inter3._records[0].request.host, "second.example")

    def test_rotate_and_read_guard_branches(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._record_spool_path = None
        inter._record_spool_fp = io.StringIO()
        inter._record_spool_max_bytes = 1024
        inter._rotate_spool_if_needed_unlocked()

        inter2 = i.Interceptor.__new__(i.Interceptor)
        inter2._record_spool_path = "/tmp/no-file.jsonl"
        inter2._record_spool_fp = None
        inter2._record_spool_max_bytes = 1024
        inter2._rotate_spool_if_needed_unlocked()

        inter3 = i.Interceptor.__new__(i.Interceptor)
        inter3._record_spool_path = "/tmp/no-file.jsonl"
        inter3._record_spool_fp = io.StringIO()
        inter3._record_spool_max_bytes = 1024
        with mock.patch.object(i.os.path, "getsize", side_effect=OSError("x")):
            inter3._rotate_spool_if_needed_unlocked()

        with tempfile.TemporaryDirectory() as d:
            p = f"{d}/rotate.jsonl"
            with open(p, "w", encoding="utf-8") as f:
                f.write("x\n")
            inter3b = i.Interceptor.__new__(i.Interceptor)
            inter3b._record_spool_path = p
            inter3b._record_spool_fp = open(p, "a", encoding="utf-8")
            inter3b._record_spool_max_bytes = 1
            inter3b._rotate_spool_if_needed_unlocked()
            self.assertTrue(i.os.path.exists(f"{p}.1.gz"))
            inter3b._record_spool_fp.close()

            p_small = f"{d}/small.jsonl"
            with open(p_small, "w", encoding="utf-8") as f:
                f.write("x")
            inter3c = i.Interceptor.__new__(i.Interceptor)
            inter3c._record_spool_path = p_small
            inter3c._record_spool_fp = open(p_small, "a", encoding="utf-8")
            inter3c._record_spool_max_bytes = 1024
            inter3c._rotate_spool_if_needed_unlocked()
            self.assertFalse(i.os.path.exists(f"{p_small}.1.gz"))
            inter3c._record_spool_fp.close()

        inter4 = i.Interceptor.__new__(i.Interceptor)
        inter4._record_spool_path = None
        self.assertEqual(inter4.get_spooled_records(), [])

        with tempfile.TemporaryDirectory() as d:
            p = f"{d}/records.jsonl"
            with open(p, "w", encoding="utf-8") as f:
                f.write("\n")
                f.write("{badjson}\n")
                f.write('{"ok":1}\n')

            inter5 = i.Interceptor.__new__(i.Interceptor)
            inter5._record_spool_path = p
            out = inter5.get_spooled_records(limit=5)
            self.assertEqual(out, [])

            store = RecordStore(record_limit=1000, spool_path=p)
            out_store = store.get_spooled_records(limit=5)
            self.assertEqual(out_store[-1]["ok"], 1)
            store.close()

            inter6 = i.Interceptor.__new__(i.Interceptor)
            inter6._record_spool_path = p
            with open(f"{p}.1.gz", "wb") as _:
                pass
            with mock.patch.object(i.gzip, "open", side_effect=OSError("x")):
                out2 = inter6.get_spooled_records(limit=5)
            self.assertIsInstance(out2, list)

    def test_interceptor_fallback_metrics_and_stop_with_lock(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        self.assertEqual(inter.get_metrics(), {})

        inter2 = i.Interceptor.__new__(i.Interceptor)
        inter2._running = True
        inter2._server = None
        inter2._record_spool_fp = io.StringIO()
        inter2._record_spool_lock = threading.Lock()
        inter2.ca = mock.Mock()
        inter2.stop()
        inter2.ca.cleanup.assert_called_once()

    def test_interceptor_record_store_delegation_paths(self):
        with tempfile.TemporaryDirectory() as d:
            spool_path = f"{d}/records.jsonl"
            inter = i.Interceptor(record_spool_path=spool_path, record_spool_max_bytes=1024, record_limit=1000)
            inter._append_record(i.ProxyRecord(request=i.InterceptedRequest(host="a"), response=i.InterceptedResponse(status_code=200)))
            self.assertTrue(inter.get_records())
            inter.clear_records()
            self.assertEqual(inter.get_records(), [])
            inter._rotate_spool_if_needed_unlocked()
            self.assertIn("total_records", inter.get_metrics())
            inter.stop()

    def test_record_store_error_and_guard_paths(self):
        store = RecordStore(record_limit=1000, spool_path=None)
        store._rotate_spool_if_needed_unlocked()
        store.spill_record(i.ProxyRecord())
        self.assertEqual(store.get_spooled_records(), [])
        store.close()

        with tempfile.TemporaryDirectory() as d:
            p = f"{d}/x.jsonl"
            store2 = RecordStore(record_limit=1000, spool_path=p)
            with mock.patch.object(i.os.path, "getsize", side_effect=OSError("x")):
                store2._rotate_spool_if_needed_unlocked()
            store2.clear()
            with open(f"{p}.1.gz", "wb"):
                pass
            with mock.patch.object(i.gzip, "open", side_effect=OSError("x")):
                out = store2.get_spooled_records(limit=5)
            self.assertIsInstance(out, list)
            store2.close()

    def test_record_store_payload_guardrails(self):
        with tempfile.TemporaryDirectory() as d:
            p = f"{d}/guard.jsonl"
            store = RecordStore(record_limit=1000, spool_path=p, spool_max_bytes=1024 * 1024)
            store.spool_max_record_bytes = 120
            huge = i.ProxyRecord(
                request=i.InterceptedRequest(host="h", path="/" + ("a" * 500)),
                response=i.InterceptedResponse(status_code=200),
                passed=True,
            )
            store.spill_record(huge)
            with open(p, "r", encoding="utf-8") as f:
                row = json.loads(f.readline())
            self.assertTrue(row["truncated"])
            self.assertEqual(row["path"], "<truncated>")

            with open(p, "a", encoding="utf-8") as f:
                f.write('{"ok":1}\n')
                f.write('{"huge":"' + ("b" * 3000) + '"}\n')
            store.spool_read_max_line_bytes = 256
            rows = store.get_spooled_records(limit=10)
            self.assertTrue(any(r.get("ok") == 1 for r in rows))
            self.assertFalse(any("huge" in r for r in rows))
            store.close()

    def test_h2session_handler_uses_record_sink_in_h1_flow(self):
        sink = mock.Mock()
        handler = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="example.com",
            port=443,
            server_alpn="http/1.1",
            callbacks={},
            magic=mock.Mock(apply=mock.Mock(return_value={"tcp": {"profile": "p"}, "tor": {"active": False}})),
            advisor=mock.Mock(advise=mock.Mock(return_value=i.AdvisorDecision(action="forward"))),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda code: code == 403,
            record_sink=sink,
        )
        req_raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp_raw = b"HTTP/1.1 200 OK\r\n\r\n"
        with mock.patch.object(
            i.H1Parser,
            "read_message",
            side_effect=[(req_raw, b""), (resp_raw, b""), (b"", b"")],
        ):
            out = handler._handle_h1_to_h1()
        self.assertEqual(len(out), 1)
        sink.assert_called_once()

    def test_interceptor_opens_and_closes_spool_file(self):
        with tempfile.TemporaryDirectory() as d:
            spool_path = f"{d}/records.jsonl"
            inter = i.Interceptor(record_spool_path=spool_path)
            self.assertIsNotNone(inter._record_spool_fp)
            inter.stop()
            self.assertIsNone(inter._record_spool_fp)

    def test_spool_rotation_compress_and_read_back(self):
        with tempfile.TemporaryDirectory() as d:
            spool_path = f"{d}/records.jsonl"
            inter = i.Interceptor(
                record_spool_path=spool_path,
                record_spool_max_bytes=50,
                record_limit=1000,
            )
            for idx in range(30):
                inter._spill_record(
                    i.ProxyRecord(
                        request=i.InterceptedRequest(
                            timestamp=float(idx),
                            method="GET",
                            host=f"h{idx}.example",
                            path="/",
                        ),
                        response=i.InterceptedResponse(status_code=200),
                        passed=True,
                    )
                )
            self.assertTrue((i.os.path.exists(spool_path)))
            self.assertTrue((i.os.path.exists(f"{spool_path}.1.gz")))
            rows = inter.get_spooled_records(limit=20)
            self.assertTrue(rows)
            self.assertLessEqual(len(rows), 20)
            inter.stop()

    def test_stop_closes_spool_without_lock(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._running = True
        inter._server = None
        inter._record_spool_fp = io.StringIO()
        inter._record_spool_lock = None
        inter.ca = mock.Mock()
        inter.stop()
        self.assertIsNone(inter._record_spool_fp)
        inter.ca.cleanup.assert_called_once()

    def test_metrics_accounting(self):
        with tempfile.TemporaryDirectory() as d:
            spool_path = f"{d}/records.jsonl"
            with open(spool_path, "w", encoding="utf-8") as f:
                f.write("{}\n")
            inter = i.Interceptor(record_limit=1000, record_spool_path=spool_path)
            inter._append_record(
                i.ProxyRecord(
                    request=i.InterceptedRequest(host="a"),
                    response=i.InterceptedResponse(status_code=200),
                    passed=True,
                    blocked=False,
                )
            )
            inter._append_record(
                i.ProxyRecord(
                    request=i.InterceptedRequest(host="b"),
                    response=i.InterceptedResponse(status_code=403),
                    passed=False,
                    blocked=True,
                )
            )
            metrics = inter.get_metrics()
            self.assertEqual(metrics["total_records"], 2)
            self.assertEqual(metrics["passed_records"], 1)
            self.assertEqual(metrics["blocked_records"], 1)
            self.assertGreater(metrics["records_per_second"], 0.0)
            self.assertGreaterEqual(metrics["spool_size_bytes"], 1)
            inter.stop()


if __name__ == "__main__":
    unittest.main()
