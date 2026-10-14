import sys
from pathlib import Path

import pytest

from conftest import PE64
from eous import pool, report


def hoard(path: Path) -> report.Analysis:
    try:
        bytearray(1 << 30)
    except MemoryError:
        return report.Analysis(path, None, report.Refusal(report.UNREADABLE, "held"))
    return report.Analysis(path, None, None)


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS enforces no memory limit")
def test_a_worker_cannot_allocate_past_its_memory_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pool, "MEMORY_BASE", 64 << 20)
    [result] = pool.analyse([PE64], hoard)
    assert result.refusal is not None
    assert result.refusal.detail == "held"


def test_a_worker_that_died_while_idle_is_replaced_before_its_next_file() -> None:
    worker = pool._start(report.analyse)
    worker.process.kill()
    worker.process.join()
    replaced = pool._assign(worker, report.analyse, iter([0]), [PE64], [PE64.stat().st_size])
    try:
        assert replaced is not worker
        assert replaced.connection.recv().digest is not None
    finally:
        replaced.connection.send(None)
        replaced.process.join()


def test_no_paths_start_no_workers() -> None:
    assert list(pool.analyse([], report.analyse)) == []
