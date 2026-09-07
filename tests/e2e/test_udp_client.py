#!/usr/bin/env python3
"""Deterministic UDP supervisor regressions: fake process/pipes/selectors/time only."""
import importlib.util
import io
from pathlib import Path
import signal
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("udp_client", Path(__file__).with_name("udp-client.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Pipe:
    def __init__(self, name):
        self.name, self.closed = name, False

    def fileno(self):
        return self.name

    def close(self):
        self.closed = True


class Process:
    def __init__(self, world):
        self.world = world
        self.stdin, self.stdout, self.stderr = (Pipe(name) for name in ("stdin", "stdout", "stderr"))
        self.returncode = None
        self.terminated_at = None
        self.killed = self.reaped = False
        self.stdin_open_at_terminate = False

    def poll(self):
        if self.world.exit_at is not None and self.world.now >= self.world.exit_at:
            self.returncode = self.world.exit_code
        return self.returncode

    def terminate(self):
        self.terminated_at = self.world.now
        self.stdin_open_at_terminate = not self.stdin.closed
        if self.world.on_terminate is not None:
            self.world.on_terminate()
        self.world.buffers["stdout"].extend(self.world.tail_on_terminate)
        if not self.world.ignore_term:
            self.returncode = -signal.SIGTERM

    def kill(self):
        self.killed = True
        self.returncode = -signal.SIGKILL

    def wait(self, timeout):
        self.world.waits.append(timeout)
        if self.returncode is None:
            self.world.now += timeout
            raise subprocess.TimeoutExpired("fake-ncat", timeout)
        self.reaped = True
        return self.returncode


class Selector:
    def __init__(self, world):
        self.world, self.entries = world, {}
        self.closed = False

    def register(self, stream, events, name):
        if self.world.registration_failure == name:
            raise RuntimeError("registration failed")
        self.entries[name] = SimpleNamespace(fileobj=stream, data=name)

    def unregister(self, stream):
        self.entries.pop(stream.name)

    def select(self, timeout):
        if self.world.on_select is not None:
            callback, self.world.on_select = self.world.on_select, None
            callback()
        self.world.select_timeouts.append(timeout)
        assert 0 <= timeout <= MODULE.POLL_SECONDS
        if "stdin" in self.entries:
            self.world.now += min(0.001, timeout)
        else:
            next_event = min((event[0] for event in self.world.events), default=float("inf"))
            self.world.now = min(self.world.now + timeout, max(self.world.now + 0.001, next_event))
        self.world.deliver()
        return [(key, 1) for name, key in self.entries.items()
                if name == "stdin" or self.world.buffers[name] or name in self.world.eof]

    def close(self):
        self.closed = True
        if self.world.selector_close_failure:
            raise RuntimeError("selector close failed")


class World:
    payload = b"openshield-udp-e2e"

    def __init__(self, reply_at=0.2, reply=None):
        self.now = 0.0
        self.spawn_delay = self.read_delay = 0.0
        self.events = [] if reply_at is None else [(reply_at, "stdout", self.payload if reply is None else reply)]
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.eof = set()
        self.written = bytearray()
        self.write_limit = None
        self.write_block_once = self.read_block_once = False
        self.exit_at = None
        self.exit_code = 0
        self.ignore_term = False
        self.tail_on_terminate = b""
        self.registration_failure = None
        self.selector_close_failure = False
        self.waits, self.select_timeouts, self.blocking_calls = [], [], []
        self.child = None
        self.selector = None
        self.argv = self.kwargs = None
        self.on_select = None
        self.on_popen = self.on_terminate = None

    def deliver(self):
        pending = []
        for when, name, data in self.events:
            if when <= self.now:
                if data is None:
                    self.eof.add(name)
                else:
                    self.buffers[name].extend(data)
            else:
                pending.append((when, name, data))
        self.events = pending

    def popen(self, argv, **kwargs):
        self.argv, self.kwargs = argv, kwargs
        self.now += self.spawn_delay
        self.child = Process(self)
        if self.on_popen is not None:
            self.on_popen()
        return self.child

    def make_selector(self):
        self.selector = Selector(self)
        return self.selector

    def write(self, fd, data):
        assert fd == "stdin" and not self.child.stdin.closed
        if self.write_block_once:
            self.write_block_once = False
            raise BlockingIOError()
        count = min(len(data), self.write_limit) if self.write_limit else len(data)
        self.written.extend(data[:count])
        return count

    def read(self, fd, size):
        if self.read_block_once and fd == "stdout" and self.child.returncode is None:
            self.read_block_once = False
            raise BlockingIOError()
        if self.buffers[fd]:
            self.now += self.read_delay if fd == "stdout" else 0
            result = bytes(self.buffers[fd][:size])
            del self.buffers[fd][:size]
            return result
        if fd in self.eof or self.child.returncode is not None:
            return b""
        raise BlockingIOError()

    def run(self):
        return MODULE.supervise("/usr/bin/ncat", "192.0.2.1", 19000, self.payload,
                                clock=lambda: self.now, popen=self.popen,
                                selector_factory=self.make_selector, read=self.read,
                                write=self.write, set_blocking=lambda fd, value: self.blocking_calls.append((fd, value)))


class SupervisorTests(unittest.TestCase):
    def assert_cleaned(self, world):
        self.assertTrue(world.child.reaped)
        self.assertTrue(all(pipe.closed for pipe in (world.child.stdin, world.child.stdout, world.child.stderr)))
        if world.selector is not None:
            self.assertTrue(world.selector.closed)

    def test_exact_argv_real_process_identity_and_no_shell(self):
        world = World()
        self.assertEqual(world.run(), world.payload)
        self.assertEqual(world.argv, ["/usr/bin/ncat", "-u", "-w", "2", "-p", "19000", "192.0.2.1", "18082"])
        self.assertNotIn("shell", world.kwargs)
        self.assertEqual(bytes(world.written), world.payload)
        self.assertTrue(world.child.stdin_open_at_terminate)
        self.assertGreaterEqual(world.child.terminated_at, 1.2)
        self.assert_cleaned(world)

    def test_slow_start_is_allowed_only_inside_original_network_budget(self):
        world = World(reply_at=1.8)
        world.spawn_delay = 1.3
        self.assertEqual(world.run(), world.payload)
        self.assertTrue(world.child.stdin_open_at_terminate)
        self.assertGreaterEqual(world.child.terminated_at, 2.8)
        self.assert_cleaned(world)

    def test_spawn_consumes_budget_and_no_payload_written_after_expiry(self):
        world = World()
        world.spawn_delay = 2.01
        with self.assertRaisesRegex(TimeoutError, "stage=spawn"):
            world.run()
        self.assertFalse(world.written)
        self.assert_cleaned(world)

    def test_valid_echo_after_deadline_rejected(self):
        world = World(reply_at=2.01)
        with self.assertRaises(TimeoutError):
            world.run()
        self.assert_cleaned(world)

    def test_final_read_and_validation_still_inside_network_deadline(self):
        world = World(reply_at=1.95)
        world.read_delay = 0.06
        with self.assertRaises(TimeoutError):
            world.run()
        self.assert_cleaned(world)

    def test_retention_does_not_extend_late_echo_budget(self):
        world = World(reply_at=1.95)
        self.assertEqual(world.run(), world.payload)
        self.assertGreaterEqual(world.child.terminated_at, 2.95)
        self.assert_cleaned(world)

    def test_eof_without_echo_not_success(self):
        world = World(reply_at=None)
        world.events = [(0.2, "stdout", None)]
        with self.assertRaisesRegex(RuntimeError, "EOF"):
            world.run()
        self.assert_cleaned(world)

    def test_prefix_followed_by_eof_not_success(self):
        world = World(reply=b"openshield")
        world.events.append((0.3, "stdout", None))
        with self.assertRaisesRegex(RuntimeError, "EOF"):
            world.run()
        self.assert_cleaned(world)

    def test_stdout_eof_after_echo_before_hold_not_success(self):
        world = World()
        world.events.append((0.3, "stdout", None))
        with self.assertRaisesRegex(RuntimeError, "EOF"):
            world.run()
        self.assert_cleaned(world)

    def test_corrupt_or_trailing_reply_not_success(self):
        for reply in (b"corrupt", World.payload + b"!"):
            with self.subTest(reply=reply):
                world = World(reply=reply)
                with self.assertRaisesRegex(RuntimeError, "corrupt|trailing"):
                    world.run()
                self.assert_cleaned(world)

    def test_trailing_data_during_retention_not_success(self):
        world = World()
        world.events.append((0.6, "stdout", b"!"))
        with self.assertRaisesRegex(RuntimeError, "trailing"):
            world.run()
        self.assert_cleaned(world)

    def test_final_pipe_drain_rejects_trailing_data(self):
        world = World()
        world.tail_on_terminate = b"!"
        with self.assertRaisesRegex(RuntimeError, "trailing"):
            world.run()
        self.assert_cleaned(world)

    def test_partial_writes_fragmented_echo_and_eagain(self):
        world = World(reply_at=None)
        world.events = [(0.2, "stdout", world.payload[:5]), (0.4, "stdout", world.payload[5:])]
        world.write_limit = 3
        world.write_block_once = world.read_block_once = True
        self.assertEqual(world.run(), world.payload)
        self.assertEqual(bytes(world.written), world.payload)
        self.assert_cleaned(world)

    def test_stderr_drain_does_not_block_echo(self):
        world = World()
        world.events.insert(0, (0.05, "stderr", b"x" * MODULE.MAX_STDERR))
        self.assertEqual(world.run(), world.payload)
        self.assert_cleaned(world)

    def test_stderr_flood_fails_bounded_and_reaps_child(self):
        world = World()
        world.events.insert(0, (0.05, "stderr", b"x" * (MODULE.MAX_STDERR + 1)))
        with self.assertRaisesRegex(RuntimeError, "bounded drain"):
            world.run()
        self.assertLess(world.now, MODULE.NETWORK_SECONDS)
        self.assert_cleaned(world)

    def test_early_process_exit_even_zero_is_not_success(self):
        world = World()
        world.exit_at = 0.3
        with self.assertRaisesRegex(RuntimeError, "exited before"):
            world.run()
        self.assert_cleaned(world)

    def test_cleanup_escalates_to_kill_and_reaps_with_bounded_waits(self):
        world = World()
        world.ignore_term = True
        self.assertEqual(world.run(), world.payload)
        self.assertTrue(world.child.killed)
        self.assertEqual(world.waits, [0.25, 1.0])
        self.assert_cleaned(world)

    def test_registration_failure_closes_all_owned_pipes(self):
        world = World()
        world.registration_failure = "stderr"
        with self.assertRaisesRegex(RuntimeError, "registration failed"):
            world.run()
        self.assert_cleaned(world)

    def test_selector_cleanup_failure_does_not_skip_child_cleanup(self):
        world = World()
        world.selector_close_failure = True
        with self.assertRaisesRegex(RuntimeError, "selector close failed"):
            world.run()
        self.assert_cleaned(world)

    def test_primary_timeout_is_not_masked_by_cleanup_error(self):
        world = World(reply_at=None)
        world.selector_close_failure = True
        with self.assertRaisesRegex(TimeoutError, "network deadline.*cleanup: selector close failed"):
            world.run()
        self.assert_cleaned(world)

    def test_sigterm_in_main_reaps_child_and_restores_previous_handler(self):
        world = World()
        previous = object()
        installed = []

        def install(signum, handler):
            self.assertEqual(signum, signal.SIGTERM)
            installed.append(handler)
            if len(installed) == 1:
                world.on_select = lambda: handler(signal.SIGTERM, None)
            return previous

        argv = ["udp-client.py", "--executable", "/usr/bin/ncat", "--peer", "192.0.2.1",
                "--payload", world.payload.decode("ascii")]
        original = MODULE.supervise

        def run_fake(*_args, **kwargs):
            return original("/usr/bin/ncat", "192.0.2.1", 19000, world.payload,
                            clock=lambda: world.now, popen=world.popen,
                            selector_factory=world.make_selector, read=world.read,
                            write=world.write, set_blocking=lambda *_: None,
                            cancellation=kwargs["cancellation"])

        with mock.patch.object(MODULE.sys, "argv", argv), \
                mock.patch.object(MODULE.signal, "signal", side_effect=install), \
                mock.patch.object(MODULE, "supervise", side_effect=run_fake):
            with self.assertRaises(SystemExit) as caught:
                MODULE.main()
        self.assertEqual(caught.exception.code, 143)
        self.assertIs(installed[-1], previous)
        self.assertTrue(world.child.stdin_open_at_terminate)
        self.assert_cleaned(world)

    def test_signal_during_popen_and_repeated_during_cleanup_cannot_orphan(self):
        world = World()
        previous = object()
        installed = []
        original = MODULE.supervise

        def install(_signum, handler):
            installed.append(handler)
            if len(installed) == 1:
                world.on_popen = lambda: handler(signal.SIGTERM, None)
                world.on_terminate = lambda: (handler(signal.SIGTERM, None), handler(signal.SIGTERM, None))
            return previous

        def run_fake(*_args, **kwargs):
            return original("/usr/bin/ncat", "192.0.2.1", 19000, world.payload,
                            clock=lambda: world.now, popen=world.popen,
                            selector_factory=world.make_selector, read=world.read,
                            write=world.write, set_blocking=lambda *_: None,
                            cancellation=kwargs["cancellation"])

        argv = ["udp-client.py", "--executable", "/usr/bin/ncat", "--peer", "192.0.2.1", "--payload", "x"]
        with mock.patch.object(MODULE.sys, "argv", argv), \
                mock.patch.object(MODULE.signal, "signal", side_effect=install), \
                mock.patch.object(MODULE, "supervise", side_effect=run_fake):
            with self.assertRaises(SystemExit) as caught:
                MODULE.main()
        self.assertEqual(caught.exception.code, 143)
        self.assertIs(installed[-1], previous)
        self.assertFalse(world.written)
        self.assertTrue(world.child.stdin_open_at_terminate)
        self.assert_cleaned(world)

    def test_signal_after_supervise_suppresses_success_output(self):
        previous = object()
        installed = []
        stdout = SimpleNamespace(buffer=io.BytesIO())

        def run_fake(*_args, **_kwargs):
            installed[0](signal.SIGTERM, None)
            return b"x"

        def install(_signum, handler):
            installed.append(handler)
            return previous

        argv = ["udp-client.py", "--executable", "/usr/bin/ncat", "--peer", "192.0.2.1", "--payload", "x"]
        with mock.patch.object(MODULE.sys, "argv", argv), \
                mock.patch.object(MODULE.sys, "stdout", stdout), \
                mock.patch.object(MODULE.signal, "signal", side_effect=install), \
                mock.patch.object(MODULE, "supervise", side_effect=run_fake):
            self.assertEqual(MODULE.main(), 143)
        self.assertEqual(stdout.buffer.getvalue(), b"")
        self.assertIs(installed[-1], previous)

    def test_main_restores_handler_after_success_and_validation_failure(self):
        argv = ["udp-client.py", "--executable", "/usr/bin/ncat", "--peer", "192.0.2.1", "--payload", "x"]
        for outcome, expected in ((b"x", 0), (RuntimeError("fake failure"), 1)):
            with self.subTest(outcome=outcome):
                previous = object()
                stdout = SimpleNamespace(buffer=io.BytesIO())
                with mock.patch.object(MODULE.sys, "argv", argv), \
                        mock.patch.object(MODULE.sys, "stdout", stdout), \
                        mock.patch.object(MODULE.sys, "stderr", io.StringIO()), \
                        mock.patch.object(MODULE.signal, "signal", return_value=previous) as setter, \
                        mock.patch.object(MODULE, "supervise") as run:
                    if isinstance(outcome, Exception):
                        run.side_effect = outcome
                    else:
                        run.return_value = outcome
                    self.assertEqual(MODULE.main(), expected)
                self.assertEqual(setter.call_args, mock.call(signal.SIGTERM, previous))

    def test_payload_bound_and_path_validation_before_spawn(self):
        for payload in (b"", b"x" * (MODULE.MAX_PAYLOAD + 1)):
            world = World()
            world.payload = payload
            with self.assertRaises(ValueError):
                world.run()
            self.assertIsNone(world.child)
        with self.assertRaises(ValueError):
            MODULE.supervise("ncat", "192.0.2.1", 19000, b"x")


class ShellIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).with_name("server-learning-enforcing.sh").read_text(encoding="utf-8")

    @staticmethod
    def command(text):
        uncommented = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        return " ".join(uncommented.replace("\\\n", " ").split())

    def udp_branches(self):
        function = self.source.split("run_udp_client() {\n", 1)[1].split("\n}\n", 1)[0]
        native, supervised = function.split("\n    else\n", 1)
        return native.split("then\n", 1)[1], supervised.rsplit("\n    fi", 1)[0]

    def test_helper_is_readonly_mounted_in_both_client_branches(self):
        marker = 'if [ -n "$native_client_source" ]; then\n    client_id='
        creation = self.source.split(marker, 1)[1].split('\nfi\ndocker start "$client_id"', 1)[0]
        branches = creation.split("\nelse\n")
        self.assertEqual(len(branches), 2)
        mount = '--mount "type=bind,src=$script_directory/udp-client.py,dst=/opt/udp-client.py,readonly"'
        self.assertEqual(self.source.count(mount), 2)
        for branch in branches:
            self.assertEqual(branch.count(mount), 1)

    def test_supervisor_invocation_has_exact_fixed_deadlines_and_payload(self):
        _native, supervised = self.udp_branches()
        self.assertEqual(self.command(supervised),
                         'docker exec "$client" python3 /opt/udp-client.py '
                         '--executable "$udp_executable" --peer "$server_ip" '
                         '--source-port 19000 --payload "$udp_payload" '
                         '--timeout-ms 2000 --hold-ms 1000')

    def test_native_c_udp_branch_is_not_replaced(self):
        native, _supervised = self.udp_branches()
        self.assertEqual(self.command(native),
                         'docker exec "$client" "$udp_executable" udp '
                         '"$server_ip" 18082 19000 2000 "$udp_payload"')
        self.assertNotIn("udp-client.py", native)


if __name__ == "__main__":
    unittest.main()
