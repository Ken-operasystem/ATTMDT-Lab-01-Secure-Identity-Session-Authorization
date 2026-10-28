"""Fixture evidence: mỗi test ghi một file evidence/Tn-*.md, cuối phiên ghi evidence/SUMMARY.md."""

from collections.abc import Callable, Iterator

import pytest

from lab_client import EVIDENCE_DIR, RESULTS, Evidence


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> Iterator[None]:
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)


@pytest.fixture
def evidence(request: pytest.FixtureRequest) -> Iterator[Callable[[str, str, str, str], Evidence]]:
    created: list[Evidence] = []

    def make(test_id: str, slug: str, title: str, pass_when: str) -> Evidence:
        ev = Evidence(test_id, slug, title, pass_when)
        created.append(ev)
        return ev

    yield make
    report = getattr(request.node, "rep_call", None)
    passed = report is not None and report.passed
    for ev in created:
        ev.write("PASS" if passed else "FAIL", None if passed or report is None else report.longreprtext)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not RESULTS:
        return
    lines = [
        "# Tổng hợp kết quả test",
        "",
        "| Test | Nội dung | Kết quả | Evidence |",
        "|---|---|---|---|",
    ]
    for test_id, (title, outcome, filename) in RESULTS.items():
        lines.append(f"| {test_id} | {title} | {outcome} | [{filename}]({filename}) |")
    (EVIDENCE_DIR / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
