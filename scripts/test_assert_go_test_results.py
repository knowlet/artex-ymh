import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from scripts.assert_go_test_results import check_results, main

PACKAGE = "example/agent"
NAMES = ["TestWireA", "TestWireB"]


def event(action, name=None, package=PACKAGE, **extra):
    result = {"Action": action, "Package": package, **extra}
    if name is not None:
        result["Test"] = name
    return json.dumps(result) + "\n"


def passing():
    return [event("run", name) for name in NAMES] + [event("pass", name) for name in NAMES] + [event("pass")]


class ResultGateTests(unittest.TestCase):
    def test_passing_events(self):
        check_results(passing(), PACKAGE, NAMES)

    def test_empty_or_no_matching_tests(self):
        for lines in [[], [event("pass")], [event("output", Output="testing: warning: no tests to run\n"), event("pass")]]:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                check_results(lines, PACKAGE, NAMES)

    def test_removed_or_renamed_test(self):
        lines = [line.replace("TestWireB", "TestRenamed") for line in passing()]
        with self.assertRaises(ValueError):
            check_results(lines, PACKAGE, NAMES)

    def test_skipped_required_test(self):
        lines = passing() + [event("skip", NAMES[0])]
        with self.assertRaises(ValueError):
            check_results(lines, PACKAGE, NAMES)

    def test_failure_cannot_be_hidden_by_pass(self):
        for failed in [event("fail"), event("fail", NAMES[0]), event("fail", "TestOther", "other/package")]:
            with self.subTest(failed=failed), self.assertRaises(ValueError):
                check_results([failed] + passing(), PACKAGE, NAMES)

    def test_wrong_package(self):
        with self.assertRaises(ValueError):
            check_results(passing(), "wrong/package", NAMES)

    def test_no_run_event(self):
        with self.assertRaises(ValueError):
            check_results([event("pass", name) for name in NAMES] + [event("pass")], PACKAGE, NAMES)

    def test_no_package_pass(self):
        with self.assertRaises(ValueError):
            check_results(passing()[:-1], PACKAGE, NAMES)

    def test_output_text_does_not_count(self):
        with self.assertRaises(ValueError):
            check_results([event("output", Output="--- PASS: TestWireA\n--- PASS: TestWireB\n"), event("pass")], PACKAGE, NAMES)

    def test_subtest_is_not_parent(self):
        with self.assertRaises(ValueError):
            check_results([line.replace("TestWireA", "TestWireA/child") for line in passing()], PACKAGE, NAMES)

    def test_invalid_input(self):
        for bad in ["not JSON", "null", "[]"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check_results([bad], PACKAGE, NAMES)

    def test_expectations_cannot_be_empty_or_duplicate(self):
        for names in [[], [NAMES[0], NAMES[0]]]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                check_results(passing(), PACKAGE, names)

    def test_cli_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            log = Path(tmp) / "events.jsonl"
            self.assertEqual(main([]), 2)
            self.assertEqual(main([str(log), PACKAGE, *NAMES]), 1)
            log.write_text("".join(passing()), encoding="utf-8")
            self.assertEqual(main([str(log), PACKAGE, *NAMES]), 0)
            log.write_text(event("pass"), encoding="utf-8")
            self.assertEqual(main([str(log), PACKAGE, *NAMES]), 1)


if __name__ == "__main__":
    unittest.main()
