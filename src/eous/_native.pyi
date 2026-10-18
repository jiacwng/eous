ICED_X86: str
VERSION: str
TARGETS: list[str]
NGRAM: int
PERMUTATIONS: int
SLOT_BITS: int

def digest(sections: list[bytes], bitness: int, target: str) -> str | None: ...
