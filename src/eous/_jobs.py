# Caps the committed memory of the current process with a Windows job object.

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

assert sys.platform == "win32"  # noqa: S101

JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
EXTENDED_LIMIT_INFORMATION = 9


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", ctypes.c_uint64 * 6),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _MemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateJobObjectW.restype = wintypes.HANDLE
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE
_kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
_kernel32.SetInformationJobObject.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
]
_kernel32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]

_job: int | None = None


def limit_memory(budget: int) -> None:
    global _job
    process = _kernel32.GetCurrentProcess()
    if _job is None:
        _job = _kernel32.CreateJobObjectW(None, None)
        _check(_job and _kernel32.AssignProcessToJobObject(_job, process))
    counters = _MemoryCounters(cb=ctypes.sizeof(_MemoryCounters))
    _check(_kernel32.K32GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb))
    limits = _ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY
    limits.ProcessMemoryLimit = counters.PagefileUsage + budget
    _check(
        _kernel32.SetInformationJobObject(
            _job, EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits), ctypes.sizeof(limits)
        )
    )


def _check(succeeded: object) -> None:
    if not succeeded:
        raise ctypes.WinError(ctypes.get_last_error())
