ICED_X86: str
VERSION: str
TARGETS: list[str]
NGRAM: int
PERMUTATIONS: int
SLOT_BITS: int
FUNCTION_BYTES: int

def digest(sections: list[bytes], bitness: int, target: str) -> str | None: ...
def differing_slots(rows: bytes, one: bytes) -> bytes: ...
def functions(
    sections: list[tuple[int, bytes]], bitness: int, target: str, entry_points: list[int]
) -> list[tuple[int, int, str]]: ...
