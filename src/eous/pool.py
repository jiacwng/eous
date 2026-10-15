# Analyses files in worker processes, each file under a memory limit and a deadline derived
# from its size. A worker that crashes or overruns is replaced and costs only its own file.

from __future__ import annotations

import contextlib
import math
import multiprocessing
import os
import signal
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from multiprocessing.connection import wait
from multiprocessing.process import BaseProcess
from pathlib import Path

from eous import report

if sys.platform == "win32":
    from multiprocessing.connection import PipeConnection as Connection
else:
    from multiprocessing.connection import Connection

MEMORY_BASE = 512 << 20
MEMORY_PER_BYTE = 4
TIME_BASE = 30.0
TIME_PER_BYTE = 1.0 / (1 << 20)
SHUTDOWN_SECONDS = 5.0
WINDOWS_WAIT_LIMIT = 61

Analyse = Callable[[Path], report.Analysis]


@dataclass
class _Worker:
    process: BaseProcess
    connection: Connection
    index: int | None = None
    deadline: float = 0.0
    seconds: float = 0.0


def analyse(paths: list[Path], analyse_one: Analyse) -> Iterator[report.Analysis]:
    sizes = [_size(path) for path in paths]
    queue = iter(range(len(paths)))
    workers = [_start(analyse_one) for _ in range(min(len(paths), _worker_count()))]
    done: dict[int, report.Analysis] = {}
    following = 0
    try:
        workers = [_assign(worker, analyse_one, queue, paths, sizes) for worker in workers]
        while following < len(paths):
            busy = [worker for worker in workers if worker.index is not None]
            nearest = min(worker.deadline for worker in busy)
            waiting = [worker.connection for worker in busy]
            ready = wait(waiting, max(0.0, nearest - time.monotonic()))
            for slot, worker in enumerate(workers):
                index = worker.index
                if index is None:
                    continue
                if worker.connection in ready:
                    try:
                        outcome = worker.connection.recv()
                    except (EOFError, OSError):
                        outcome = report.crashed(paths[index])
                        worker = _replace(worker, analyse_one)
                    if isinstance(outcome, BaseException):
                        raise outcome
                elif time.monotonic() >= worker.deadline:
                    outcome = report.overran(paths[index], worker.seconds)
                    worker = _replace(worker, analyse_one)
                else:
                    continue
                done[index] = outcome
                worker.index = None
                workers[slot] = _assign(worker, analyse_one, queue, paths, sizes)
            while following in done:
                yield done.pop(following)
                following += 1
    finally:
        for worker in workers:
            with contextlib.suppress(OSError):
                worker.connection.send(None)
        end = time.monotonic() + SHUTDOWN_SECONDS
        for worker in workers:
            worker.process.join(max(0.0, end - time.monotonic()))
            worker.process.kill()
            worker.process.join()
            worker.connection.close()


def _worker_count() -> int:
    count = os.cpu_count() or 1
    return min(count, WINDOWS_WAIT_LIMIT) if sys.platform == "win32" else count


def _size(path: Path) -> int:
    try:
        return os.stat(path).st_size
    except (OSError, ValueError):
        return 0


def _start(analyse_one: Analyse) -> _Worker:
    parent, child = multiprocessing.Pipe()
    process = multiprocessing.Process(target=_work, args=(child, analyse_one), daemon=True)
    process.start()
    child.close()
    return _Worker(process, parent)


def _replace(worker: _Worker, analyse_one: Analyse) -> _Worker:
    worker.process.kill()
    worker.process.join()
    worker.connection.close()
    return _start(analyse_one)


def _assign(
    worker: _Worker,
    analyse_one: Analyse,
    queue: Iterator[int],
    paths: list[Path],
    sizes: list[int],
) -> _Worker:
    index = next(queue, None)
    if index is None:
        return worker
    seconds = TIME_BASE + TIME_PER_BYTE * sizes[index]
    task = (paths[index], MEMORY_BASE + MEMORY_PER_BYTE * sizes[index], seconds)
    try:
        worker.connection.send(task)
    except OSError:
        worker = _replace(worker, analyse_one)
        worker.connection.send(task)
    worker.index = index
    worker.seconds = seconds
    worker.deadline = time.monotonic() + seconds
    return worker


def _work(connection: Connection, analyse_one: Analyse) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    parent = multiprocessing.parent_process()
    watched: list[Connection | int] = [connection]
    if parent is not None:
        watched.append(parent.sentinel)
    while True:
        if connection not in wait(watched):
            return
        try:
            task = connection.recv()
        except EOFError:
            return
        if task is None:
            return
        path, budget, seconds = task
        _limit_memory(budget)
        _limit_time(math.ceil(seconds) + 1)
        try:
            outcome: object = analyse_one(path)
        except Exception as exc:
            outcome = exc
        _limit_time(0)
        connection.send(outcome)


# The parent enforces the deadline. This alarm only ends a worker whose parent is gone,
# and Windows has no alarm.
def _limit_time(seconds: int) -> None:
    if sys.platform != "win32":
        import signal

        signal.alarm(seconds)


# The budget sits on top of what the worker already holds. Linux counts address space,
# Windows counts committed memory, and macOS enforces neither, so there only the deadline holds.
def _limit_memory(budget: int) -> None:
    if sys.platform == "linux":
        import resource

        with open("/proc/self/statm") as statm:
            held = int(statm.read().split()[0]) * os.sysconf("SC_PAGE_SIZE")
        hard = resource.getrlimit(resource.RLIMIT_AS)[1]
        soft = held + budget
        if hard != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
    elif sys.platform == "win32":
        from eous import _jobs

        _jobs.limit_memory(budget)
