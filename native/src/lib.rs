// Turns executable code bytes into an EO1 digest: instruction, root, shingle, sketch.
// The same pipeline digests each function of a file, once it has found where they start.

use std::collections::HashMap;
use std::sync::OnceLock;

use blake2b_simd::Params;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};

const ROOTS_JSON: &str = include_str!("../roots.json");
const OOV: &str = "<oov>";
const VERSION: &str = "EO1";
const TARGETS: [&str; 4] = ["pe32", "pe64", "elf32", "elf64"];
const BITNESSES: [u32; 2] = [32, 64];

const NGRAM: usize = 3;
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
const FUNCTION_BYTES: u64 = 256;

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

// Each shingle is three root ids packed into one integer, so equal shingles are equal keys.
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

fn disassemble(data: &[u8], bitness: u32, ids: &[u8], shingles: &mut Shingles, cut: bool) {
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

        if cut
            && !matches!(
                instruction.flow_control(),
                FlowControl::Next | FlowControl::Interrupt
            )
        {
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

fn check(bitness: u32, target: &str) -> Result<(), String> {
    if !BITNESSES.contains(&bitness) {
        return Err(format!("unsupported bitness {bitness}"));
    }
    if !TARGETS.contains(&target) {
        return Err(format!("unsupported target {target:?}"));
    }
    Ok(())
}

fn render(keys: &[u64], target: &str, names: &[String]) -> Option<String> {
    let mut seen = [false; 1 << ROOT_BITS];
    keys.iter()
        .flat_map(|&key| root_ids(key))
        .for_each(|id| seen[id] = true);
    if seen.iter().filter(|&&found| found).count() < 2 {
        return None;
    }
    let body = sketch(keys, names);
    Some(format!("{VERSION}:{target}:{}:{body}", keys.len()))
}

fn digest_of<S: AsRef<[u8]>>(
    sections: &[S],
    bitness: u32,
    target: &str,
) -> Result<Option<String>, String> {
    check(bitness, target)?;
    let vocabulary = vocabulary();
    let mut shingles = Shingles::new();
    for section in sections {
        disassemble(
            section.as_ref(),
            bitness,
            &vocabulary.ids,
            &mut shingles,
            true,
        );
    }
    Ok(render(&shingles.finish(), target, &vocabulary.names))
}

fn is_near(instruction: &Instruction) -> bool {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

fn marked(bits: &[u64], place: usize) -> bool {
    (bits[place / 64] >> (place % 64)) & 1 == 1
}

fn mark(bits: &mut [u64], place: usize) {
    bits[place / 64] |= 1 << (place % 64);
}

// One bit per byte of a section, so the finder holds a fixed share of the code it reads.
struct Code<'a> {
    address: u64,
    data: &'a [u8],
    instructions: Vec<u64>,
    ends: Vec<u64>,
    starts: Vec<u64>,
}

fn locate(codes: &[Code], address: u64) -> Option<(usize, usize)> {
    let index = codes
        .partition_point(|code| code.address <= address)
        .checked_sub(1)?;
    let place = usize::try_from(address - codes[index].address).ok()?;
    (place < codes[index].data.len()).then_some((index, place))
}

fn propose(codes: &mut [Code], address: u64) {
    if let Some((index, place)) = locate(codes, address) {
        mark(&mut codes[index].starts, place);
    }
}

fn sweep(codes: &mut [Code], index: usize, bitness: u32) {
    let (address, data) = (codes[index].address, codes[index].data);
    let mut decoder = Decoder::with_ip(bitness, data, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        let position = decoder.position();
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            decoder
                .set_position(position + 1)
                .expect("the next byte is inside the section");
            decoder.set_ip(address.wrapping_add(position as u64 + 1));
            continue;
        }
        mark(&mut codes[index].instructions, position);
        match instruction.flow_control() {
            FlowControl::Call
                if is_near(&instruction)
                    && instruction.near_branch_target() != instruction.next_ip() =>
            {
                propose(codes, instruction.near_branch_target());
            }
            FlowControl::UnconditionalBranch
            | FlowControl::Return
            | FlowControl::IndirectBranch => {
                mark(&mut codes[index].ends, decoder.position());
            }
            _ => {}
        }
    }
}

fn jump_target(code: &Code, place: usize, bitness: u32) -> Option<u64> {
    let ip = code.address.wrapping_add(place as u64);
    let mut decoder = Decoder::with_ip(bitness, &code.data[place..], ip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    (instruction.flow_control() == FlowControl::UnconditionalBranch && is_near(&instruction))
        .then(|| instruction.near_branch_target())
}

// A function starts at the target of a direct call or at an entry point, each followed
// through direct jumps and kept when it falls on an instruction of the linear sweep. It ends
// after its last return or unconditional jump before the next start.
fn bounds<'a, S: AsRef<[u8]>>(
    sections: &'a [(u64, S)],
    bitness: u32,
    entry_points: &[u64],
) -> Vec<Code<'a>> {
    let mut codes: Vec<Code> = sections
        .iter()
        .map(|(address, data)| {
            let data = data.as_ref();
            let words = data.len() / 64 + 1;
            Code {
                address: *address,
                data,
                instructions: vec![0; words],
                ends: vec![0; words],
                starts: vec![0; words],
            }
        })
        .collect();
    codes.sort_by_key(|code| code.address);

    for index in 0..codes.len() {
        sweep(&mut codes, index, bitness);
    }
    for &address in entry_points {
        propose(&mut codes, address);
    }

    let mut reached = Vec::new();
    for (index, code) in codes.iter_mut().enumerate() {
        for (word, (starts, instructions)) in
            code.starts.iter_mut().zip(&code.instructions).enumerate()
        {
            *starts &= instructions;
            reached.extend(
                (0..64)
                    .filter(|bit| (*starts >> bit) & 1 == 1)
                    .map(|bit| (index, word * 64 + bit)),
            );
        }
    }
    while let Some((index, place)) = reached.pop() {
        let followed = jump_target(&codes[index], place, bitness)
            .and_then(|target| locate(&codes, target))
            .filter(|&(index, place)| {
                marked(&codes[index].instructions, place) && !marked(&codes[index].starts, place)
            });
        if let Some((index, place)) = followed {
            mark(&mut codes[index].starts, place);
            reached.push((index, place));
        }
    }
    codes
}

// A shingle may cross a branch inside a function, since the function already bounds it.
fn functions_of<S: AsRef<[u8]>>(
    sections: &[(u64, S)],
    bitness: u32,
    target: &str,
    entry_points: &[u64],
) -> Result<Vec<(u64, u64, String)>, String> {
    check(bitness, target)?;
    let vocabulary = vocabulary();
    let mut found = Vec::new();
    for code in bounds(sections, bitness, entry_points) {
        let mut limit = code.data.len();
        for start in (0..code.data.len()).rev() {
            if !marked(&code.starts, start) {
                continue;
            }
            let end = (start + 1..=limit)
                .rev()
                .find(|&place| marked(&code.ends, place))
                .unwrap_or(limit);
            limit = start;
            if ((end - start) as u64) < FUNCTION_BYTES {
                continue;
            }
            let mut shingles = Shingles::new();
            disassemble(
                &code.data[start..end],
                bitness,
                &vocabulary.ids,
                &mut shingles,
                false,
            );
            if let Some(text) = render(&shingles.finish(), target, &vocabulary.names) {
                let address = code.address.wrapping_add(start as u64);
                found.push((address, (end - start) as u64, text));
            }
        }
    }
    found.sort_unstable_by_key(|&(address, _, _)| address);
    Ok(found)
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

    #[pyfunction]
    fn functions(
        py: Python<'_>,
        sections: Vec<(u64, PyBackedBytes)>,
        bitness: u32,
        target: &str,
        entry_points: Vec<u64>,
    ) -> PyResult<Vec<(u64, u64, String)>> {
        py.detach(|| super::functions_of(&sections, bitness, target, &entry_points))
            .map_err(PyValueError::new_err)
    }

    #[pymodule]
    fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
        module.add_function(wrap_pyfunction!(digest, module)?)?;
        module.add_function(wrap_pyfunction!(functions, module)?)?;
        module.add("FUNCTION_BYTES", super::FUNCTION_BYTES)?;
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
        code(&[XOR, middle, XOR_PUSH])
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
        assert_eq!(one(code(&[XOR, RET])), None);
        assert!(one(code(&[XOR_PUSH, XOR])).is_some());
    }

    #[test]
    fn control_flow_ends_a_run() {
        for (encoding, name) in ENDS_A_RUN {
            assert_eq!(one(around(encoding)), None, "{name} left the run open");
            assert!(
                one(code(&[XOR_PUSH, encoding])).is_some(),
                "{name} left its shingle"
            );
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
    fn a_repeat_past_three_adds_no_shingle() {
        let nops = |count: usize| one(code(&[XOR_PUSH, &NOP.repeat(count), XOR_PUSH]));
        assert!(nops(3).is_some());
        assert_ne!(nops(2), nops(3));
        assert_eq!(nops(3), nops(4));
        assert_eq!(nops(3), nops(40));
    }

    #[test]
    fn a_run_never_crosses_from_one_section_into_the_next() {
        let half = XOR_PUSH.to_vec();
        assert_eq!(digest64(&[half.clone(), half.clone()]), None);
        assert!(one(half.repeat(2)).is_some());
    }

    #[test]
    fn the_cardinality_counts_distinct_shingles() {
        assert_eq!(cardinality(&one(code(&[XOR_PUSH, XOR])).unwrap()), 1);
        assert_eq!(cardinality(&one(XOR_PUSH.repeat(2)).unwrap()), 2);
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
        let text = one(code(&[XOR_PUSH, XOR])).unwrap();
        let fields: Vec<&str> = text.split(':').collect();
        assert_eq!(fields[..3], ["EO1", "pe64", "1"]);
        assert_eq!(fields[3].len(), PERMUTATIONS * SLOT_BITS as usize / 4);
        assert!(fields[3].bytes().all(|c| c.is_ascii_hexdigit()));
    }

    const BASE: u64 = 0x1000;
    const CALL_PAST_THE_RETURN: &[u8] = b"\xe8\x01\x00\x00\x00";
    const CALL_THE_NEXT_INSTRUCTION: &[u8] = b"\xe8\x00\x00\x00\x00";
    const JUMP_TO_THE_NEXT_INSTRUCTION: &[u8] = b"\xe9\x00\x00\x00\x00";
    const JE: &[u8] = b"\x74\x00";

    fn body() -> Vec<u8> {
        code(&[&XOR_PUSH.repeat(100), RET])
    }

    fn found(section: Vec<u8>, entry_points: &[u64]) -> Vec<(u64, u64, String)> {
        functions_of(&[(BASE, section)], 64, "pe64", entry_points)
            .expect("a supported bitness and target")
    }

    fn places(functions: &[(u64, u64, String)]) -> Vec<(u64, u64)> {
        functions
            .iter()
            .map(|&(start, length, _)| (start, length))
            .collect()
    }

    #[test]
    fn a_called_address_starts_a_function_that_ends_at_its_last_return() {
        let section = code(&[CALL_PAST_THE_RETURN, RET, &body(), &NOP.repeat(8)]);
        assert_eq!(places(&found(section, &[])), [(BASE + 6, 301)]);
    }

    #[test]
    fn an_entry_point_that_jumps_also_starts_its_destination() {
        let section = code(&[JUMP_TO_THE_NEXT_INSTRUCTION, &body()]);
        assert_eq!(places(&found(section, &[BASE])), [(BASE + 5, 301)]);
    }

    #[test]
    fn a_call_to_the_next_instruction_starts_nothing() {
        let section = code(&[CALL_THE_NEXT_INSTRUCTION, &body()]);
        assert!(found(section, &[]).is_empty());
    }

    #[test]
    fn a_start_off_an_instruction_or_outside_the_code_is_dropped() {
        assert!(found(body(), &[BASE + 1, BASE - 1, u64::MAX]).is_empty());
        assert_eq!(places(&found(body(), &[BASE])), [(BASE, 301)]);
    }

    #[test]
    fn a_jump_to_itself_ends_the_chain() {
        let section = code(&[b"\xeb\xfe", &body()]);
        assert_eq!(places(&found(section, &[BASE])), [(BASE, 303)]);
    }

    #[test]
    fn the_next_start_bounds_a_function_that_never_returns() {
        let open = XOR_PUSH.repeat(100);
        let section = code(&[&open, &body()]);
        let both = [BASE, BASE + 300];
        assert_eq!(
            places(&found(section, &both)),
            [(BASE, 300), (BASE + 300, 301)]
        );
    }

    #[test]
    fn a_function_under_256_bytes_gets_no_digest() {
        let short = code(&[&XOR_PUSH.repeat(84), RET]);
        assert!(found(short, &[BASE]).is_empty());
        let long = code(&[&XOR_PUSH.repeat(85), RET]);
        assert_eq!(places(&found(long, &[BASE])), [(BASE, 256)]);
    }

    #[test]
    fn a_branch_inside_a_function_does_not_end_the_run() {
        let padding = NOP.repeat(300);
        let cardinality_with = |middle: &[u8]| {
            let section = code(&[XOR, middle, XOR_PUSH, &padding, RET]);
            cardinality(&found(section, &[BASE])[0].2)
        };
        assert!(cardinality_with(JE) > cardinality_with(b""));
    }

    #[test]
    fn hostile_code_ends_in_functions_or_none_without_panicking() {
        let mut state = 20_261_124_u64;
        let noise: Vec<u8> = (0..65_536)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (state >> 56) as u8
            })
            .collect();
        let overlapping = [(u64::MAX - 100, noise.clone()), (u64::MAX - 50, noise)];
        for bitness in BITNESSES {
            let entry_points = [0, u64::MAX - 100, u64::MAX];
            functions_of(&overlapping, bitness, "pe64", &entry_points).unwrap();
        }
        assert!(found(Vec::new(), &[BASE]).is_empty());
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
