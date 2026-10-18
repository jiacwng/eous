// Turns executable code bytes into an EO1 digest: instruction, root, shingle, sketch.

use std::collections::HashMap;
use std::sync::OnceLock;

use blake2b_simd::Params;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};

const ROOTS_JSON: &str = include_str!("../roots.json");
const OOV: &str = "<oov>";
const VERSION: &str = "EO1";
const TARGETS: [&str; 4] = ["pe32", "pe64", "elf32", "elf64"];
const BITNESSES: [u32; 2] = [32, 64];

const NGRAM: usize = 6;
const PERMUTATIONS: usize = 256;
const SLOT_BITS: u32 = 2;
const MODULUS: u64 = (1 << 61) - 1;
const SEPARATOR: u8 = 0x1f;
const PERMUTATION_PERSON: &[u8] = b"eous-prm";
const SHINGLE_PERSON: &[u8] = b"eous-ng";

const ROOT_BITS: u32 = 7;
const ROOT_MASK: u64 = (1 << ROOT_BITS) - 1;
const SHINGLE_MASK: u64 = (1 << (ROOT_BITS * NGRAM as u32)) - 1;
const COMPACT_FLOOR: usize = 1 << 22;

struct Vocabulary {
    names: Vec<String>,
    ids: Vec<u8>,
}

fn roots() -> HashMap<String, String> {
    serde_json::from_str(ROOTS_JSON).expect("roots.json is a flat object of strings")
}

fn mnemonic_name(mnemonic: Mnemonic) -> String {
    format!("{mnemonic:?}").to_lowercase()
}

fn vocabulary() -> &'static Vocabulary {
    static VOCABULARY: OnceLock<Vocabulary> = OnceLock::new();
    VOCABULARY.get_or_init(|| {
        let table = roots();
        let mut names: Vec<String> = Vec::new();
        let ids = Mnemonic::values()
            .map(|mnemonic| {
                let root = table
                    .get(&mnemonic_name(mnemonic))
                    .map_or(OOV, String::as_str);
                let id = names
                    .iter()
                    .position(|known| known == root)
                    .unwrap_or_else(|| {
                        names.push(root.to_owned());
                        names.len() - 1
                    });
                id as u8
            })
            .collect();
        assert!(
            names.len() <= 1 << ROOT_BITS,
            "roots exceed the shingle key width"
        );
        Vocabulary { names, ids }
    })
}

fn h64(payload: &[u8], person: &[u8]) -> u64 {
    let hash = Params::new().hash_length(8).personal(person).hash(payload);
    u64::from_be_bytes(hash.as_bytes().try_into().expect("an 8 byte hash"))
}

fn coefficients() -> &'static [(u64, u64)] {
    static COEFFICIENTS: OnceLock<Vec<(u64, u64)>> = OnceLock::new();
    COEFFICIENTS.get_or_init(|| {
        (0..PERMUTATIONS as u32)
            .map(|index| {
                let label = index.to_be_bytes();
                let multiplier =
                    h64(&[b"a", &label[..]].concat(), PERMUTATION_PERSON) % (MODULUS - 1) + 1;
                let offset = h64(&[b"b", &label[..]].concat(), PERMUTATION_PERSON) % MODULUS;
                (multiplier, offset)
            })
            .collect()
    })
}

// Each shingle is six root ids packed into one integer, so equal shingles are equal keys.
struct Shingles {
    key: u64,
    filled: usize,
    keys: Vec<u64>,
    compact_at: usize,
}

impl Shingles {
    fn new() -> Self {
        Self {
            key: 0,
            filled: 0,
            keys: Vec::new(),
            compact_at: COMPACT_FLOOR,
        }
    }

    fn push(&mut self, root: u8) {
        self.key = ((self.key << ROOT_BITS) | u64::from(root)) & SHINGLE_MASK;
        self.filled += 1;
        if self.filled >= NGRAM {
            self.keys.push(self.key);
            if self.keys.len() >= self.compact_at {
                self.compact();
                self.compact_at = (self.keys.len() * 2).max(COMPACT_FLOOR);
            }
        }
    }

    fn end_run(&mut self) {
        self.filled = 0;
    }

    fn compact(&mut self) {
        self.keys.sort_unstable();
        self.keys.dedup();
    }

    fn finish(mut self) -> Vec<u64> {
        self.compact();
        self.keys
    }
}

fn disassemble(data: &[u8], bitness: u32, ids: &[u8], shingles: &mut Shingles) {
    let mut decoder = Decoder::new(bitness, data, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut previous = None;
    let mut repeated = 0;

    while decoder.can_decode() {
        let position = decoder.position();
        decoder.decode_out(&mut instruction);

        if instruction.is_invalid() {
            decoder
                .set_position(position + 1)
                .expect("the next byte is inside the section");
            shingles.end_run();
            previous = None;
            continue;
        }

        let mnemonic = instruction.mnemonic();
        repeated = if previous == Some(mnemonic) {
            repeated + 1
        } else {
            1
        };
        previous = Some(mnemonic);
        if repeated <= NGRAM {
            shingles.push(ids[mnemonic as usize]);
        }

        if !matches!(
            instruction.flow_control(),
            FlowControl::Next | FlowControl::Interrupt
        ) {
            shingles.end_run();
            previous = None;
        }
    }
    shingles.end_run();
}

fn root_ids(key: u64) -> impl Iterator<Item = usize> {
    (0..NGRAM)
        .rev()
        .map(move |place| ((key >> (ROOT_BITS * place as u32)) & ROOT_MASK) as usize)
}

fn permute(multiplier: u64, offset: u64, value: u64) -> u64 {
    let product = u128::from(multiplier) * u128::from(value) + u128::from(offset);
    let folded = (product as u64 & MODULUS) + (product >> 61) as u64;
    let reduced = (folded & MODULUS) + (folded >> 61);
    if reduced >= MODULUS {
        reduced - MODULUS
    } else {
        reduced
    }
}

fn sketch(keys: &[u64], names: &[String]) -> String {
    let coefficients = coefficients();
    let mut smallest = [MODULUS; PERMUTATIONS];
    let mut payload = Vec::with_capacity(128);
    for &key in keys {
        payload.clear();
        for (place, id) in root_ids(key).enumerate() {
            if place > 0 {
                payload.push(SEPARATOR);
            }
            payload.extend_from_slice(names[id].as_bytes());
        }
        let value = h64(&payload, SHINGLE_PERSON) % MODULUS;
        for (slot, &(multiplier, offset)) in smallest.iter_mut().zip(coefficients) {
            *slot = (*slot).min(permute(multiplier, offset, value));
        }
    }
    let slot_mask = (1 << SLOT_BITS) - 1;
    smallest
        .chunks((u8::BITS / SLOT_BITS) as usize)
        .map(|slots| {
            slots.iter().fold(0u8, |byte, &slot| {
                (byte << SLOT_BITS) | (slot & slot_mask) as u8
            })
        })
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn digest_of<S: AsRef<[u8]>>(
    sections: &[S],
    bitness: u32,
    target: &str,
) -> Result<Option<String>, String> {
    if !BITNESSES.contains(&bitness) {
        return Err(format!("unsupported bitness {bitness}"));
    }
    if !TARGETS.contains(&target) {
        return Err(format!("unsupported target {target:?}"));
    }
    let vocabulary = vocabulary();
    let mut shingles = Shingles::new();
    for section in sections {
        disassemble(section.as_ref(), bitness, &vocabulary.ids, &mut shingles);
    }
    let keys = shingles.finish();

    let mut seen = [false; 1 << ROOT_BITS];
    keys.iter()
        .flat_map(|&key| root_ids(key))
        .for_each(|id| seen[id] = true);
    if seen.iter().filter(|&&found| found).count() < 2 {
        return Ok(None);
    }
    let body = sketch(&keys, &vocabulary.names);
    Ok(Some(format!("{VERSION}:{target}:{}:{body}", keys.len())))
}

#[cfg(feature = "python")]
mod python {
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;
    use pyo3::pybacked::PyBackedBytes;

    const ICED_X86: &str = "1.21.0";

    #[pyfunction]
    fn digest(
        py: Python<'_>,
        sections: Vec<PyBackedBytes>,
        bitness: u32,
        target: &str,
    ) -> PyResult<Option<String>> {
        py.detach(|| super::digest_of(&sections, bitness, target))
            .map_err(PyValueError::new_err)
    }

    #[pymodule]
    fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
        module.add_function(wrap_pyfunction!(digest, module)?)?;
        module.add("ICED_X86", ICED_X86)?;
        module.add("VERSION", super::VERSION)?;
        module.add("TARGETS", super::TARGETS)?;
        module.add("NGRAM", super::NGRAM)?;
        module.add("PERMUTATIONS", super::PERMUTATIONS)?;
        module.add("SLOT_BITS", super::SLOT_BITS)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XOR_PUSH: &[u8] = b"\x31\xc0\x50";
    const XOR: &[u8] = b"\x31\xc0";
    const RET: &[u8] = b"\xc3";
    const NOP: &[u8] = b"\x90";
    const INVALID_IN_64_BIT: &[u8] = b"\x06";

    const ENDS_A_RUN: [(&[u8], &str); 8] = [
        (b"\xc3", "ret"),
        (b"\xeb\x00", "jmp"),
        (b"\xff\xe0", "jmp rax"),
        (b"\xe8\x00\x00\x00\x00", "call"),
        (b"\xff\xd0", "call rax"),
        (b"\x74\x00", "je"),
        (b"\x0f\x05", "syscall"),
        (b"\x0f\x0b", "ud2"),
    ];
    const FALLS_THROUGH: [(&[u8], &str); 2] = [(b"\xcc", "int3"), (b"\x90", "nop")];

    fn code(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn digest64(sections: &[Vec<u8>]) -> Option<String> {
        digest_of(sections, 64, "pe64").expect("a supported bitness and target")
    }

    fn one(data: Vec<u8>) -> Option<String> {
        digest64(&[data])
    }

    fn cardinality(text: &str) -> usize {
        text.split(':').nth(2).unwrap().parse().unwrap()
    }

    fn around(middle: &[u8]) -> Vec<u8> {
        code(&[XOR_PUSH, XOR, middle, XOR_PUSH, XOR])
    }

    #[test]
    fn every_mnemonic_iced_emits_has_a_root() {
        let placeholders = ["invalid", "db", "dw", "dd", "dq", "zero_bytes"];
        let table = roots();
        let missing: Vec<String> = Mnemonic::values()
            .map(mnemonic_name)
            .filter(|name| !placeholders.contains(&name.as_str()) && !table.contains_key(name))
            .collect();
        assert!(missing.is_empty(), "no root for {missing:?}");
    }

    #[test]
    fn a_run_shorter_than_a_shingle_gives_no_digest() {
        assert_eq!(one(code(&[XOR_PUSH, XOR_PUSH, RET])), None);
        assert!(one(XOR_PUSH.repeat(3)).is_some());
    }

    #[test]
    fn control_flow_ends_a_run() {
        for (encoding, name) in ENDS_A_RUN {
            assert_eq!(one(around(encoding)), None, "{name} left the run open");
        }
    }

    #[test]
    fn an_interrupt_and_a_plain_instruction_fall_through() {
        for (encoding, name) in FALLS_THROUGH {
            assert!(one(around(encoding)).is_some(), "{name} ended the run");
        }
    }

    #[test]
    fn an_invalid_byte_ends_the_run_and_decoding_resumes_after_it() {
        assert_eq!(one(around(INVALID_IN_64_BIT)), None);
        assert!(one(code(&[INVALID_IN_64_BIT, &XOR_PUSH.repeat(3)])).is_some());
    }

    #[test]
    fn a_repeat_past_six_adds_no_shingle() {
        let nops = |count: usize| one(code(&[XOR_PUSH, &NOP.repeat(count), XOR_PUSH]));
        assert!(nops(6).is_some());
        assert_ne!(nops(5), nops(6));
        assert_eq!(nops(6), nops(7));
        assert_eq!(nops(6), nops(40));
    }

    #[test]
    fn a_run_never_crosses_from_one_section_into_the_next() {
        let half = code(&[XOR_PUSH, XOR]);
        assert_eq!(digest64(&[half.clone(), half.clone()]), None);
        assert!(one(half.repeat(2)).is_some());
    }

    #[test]
    fn the_cardinality_counts_distinct_shingles() {
        assert_eq!(cardinality(&one(XOR_PUSH.repeat(3)).unwrap()), 1);
        assert_eq!(cardinality(&one(XOR_PUSH.repeat(4)).unwrap()), 2);
        assert_eq!(cardinality(&one(XOR_PUSH.repeat(40)).unwrap()), 2);
    }

    #[test]
    fn a_single_root_gives_no_digest() {
        assert_eq!(one(NOP.repeat(20)), None);
    }

    #[test]
    fn section_order_does_not_change_the_digest() {
        let first = code(&[&XOR_PUSH.repeat(3), RET]);
        let second = around(NOP);
        assert_eq!(
            digest64(&[first.clone(), second.clone()]),
            digest64(&[second, first])
        );
    }

    #[test]
    fn a_digest_has_the_eo1_layout() {
        let text = one(XOR_PUSH.repeat(3)).unwrap();
        let fields: Vec<&str> = text.split(':').collect();
        assert_eq!(fields[..3], ["EO1", "pe64", "1"]);
        assert_eq!(fields[3].len(), PERMUTATIONS * SLOT_BITS as usize / 4);
        assert!(fields[3].bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn the_permutation_is_exact_modular_arithmetic() {
        let mut values = vec![0, 1, 2, MODULUS - 2, MODULUS - 1];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..1000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            values.push(state % MODULUS);
        }
        for &(multiplier, offset) in coefficients().iter().take(16) {
            for &value in &values {
                let exact = (u128::from(multiplier) * u128::from(value) + u128::from(offset))
                    % u128::from(MODULUS);
                assert_eq!(u128::from(permute(multiplier, offset, value)), exact);
            }
        }
    }

    #[test]
    fn hostile_code_ends_in_a_digest_or_none_without_panicking() {
        let mut state = 20_261_013_u64;
        let noise: Vec<u8> = (0..65_536)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (state >> 56) as u8
            })
            .collect();
        assert_eq!(one(Vec::new()), None);
        assert_eq!(one(b"\xcc".repeat(64)), None);
        assert_eq!(one(b"\xff\xff".repeat(32)), None);
        assert!(one(code(&[&XOR_PUSH.repeat(4), RET]).repeat(50)).is_some());
        assert!(one(noise).is_some());
    }
}
