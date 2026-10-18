// Turns executable code bytes into an EO1 digest: instruction, root, shingle, sketch.

use std::collections::HashMap;
use std::sync::OnceLock;

use blake2b_simd::Params;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;

const ICED_X86: &str = "1.21.0";
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

fn vocabulary() -> &'static Vocabulary {
    static VOCABULARY: OnceLock<Vocabulary> = OnceLock::new();
    VOCABULARY.get_or_init(|| {
        let table: HashMap<String, String> =
            serde_json::from_str(ROOTS_JSON).expect("roots.json is a flat object of strings");
        let mut names: Vec<String> = Vec::new();
        let ids = Mnemonic::values()
            .map(|mnemonic| {
                let name = format!("{mnemonic:?}").to_lowercase();
                let root = table.get(&name).map_or(OOV, String::as_str);
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

#[pyfunction]
fn digest(
    py: Python<'_>,
    sections: Vec<PyBackedBytes>,
    bitness: u32,
    target: &str,
) -> PyResult<Option<String>> {
    if !BITNESSES.contains(&bitness) {
        return Err(PyValueError::new_err(format!(
            "unsupported bitness {bitness}"
        )));
    }
    if !TARGETS.contains(&target) {
        return Err(PyValueError::new_err(format!(
            "unsupported target {target:?}"
        )));
    }
    let vocabulary = vocabulary();
    Ok(py.detach(|| {
        let mut shingles = Shingles::new();
        for section in &sections {
            disassemble(section, bitness, &vocabulary.ids, &mut shingles);
        }
        let keys = shingles.finish();

        let mut seen = [false; 1 << ROOT_BITS];
        keys.iter()
            .flat_map(|&key| root_ids(key))
            .for_each(|id| seen[id] = true);
        if seen.iter().filter(|&&found| found).count() < 2 {
            return None;
        }
        let body = sketch(&keys, &vocabulary.names);
        Some(format!("{VERSION}:{target}:{}:{body}", keys.len()))
    }))
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(digest, module)?)?;
    module.add("ICED_X86", ICED_X86)?;
    module.add("VERSION", VERSION)?;
    module.add("TARGETS", TARGETS)?;
    module.add("NGRAM", NGRAM)?;
    module.add("PERMUTATIONS", PERMUTATIONS)?;
    module.add("SLOT_BITS", SLOT_BITS)?;
    Ok(())
}
