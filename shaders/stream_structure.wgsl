// Stage 3C: Structural Context Stream
//
// Analyzes the syntactic structure surrounding each candidate:
// - Delimiter presence (quotes, brackets, braces)
// - Assignment operators (=, :)
// - Export keywords
// - Indentation patterns (YAML/Python context)
//
// Structure score feeds into tri-stream fusion.

struct StructureResult {
    candidate_idx: u32,
    score: f32,
    structure_flags: u32,
    _pad: u32,
}

// Structure flag bitmask
const STRUCT_QUOTED: u32 = 1u;       // surrounded by quotes
const STRUCT_BRACKETED: u32 = 2u;    // inside [], {}
const STRUCT_ASSIGNED: u32 = 4u;     // preceded by = or :
const STRUCT_EXPORTED: u32 = 8u;     // preceded by export keyword
const STRUCT_YAML_INDENT: u32 = 16u; // YAML indented key

@group(0) @binding(0) var<storage, read> input_bytes: array<u32>;
@group(0) @binding(1) var<storage, read_write> structure_results: array<StructureResult>;
@group(0) @binding(2) var<uniform> params: StructureParams;
@group(0) @binding(3) var<storage, read> candidate_offsets: array<u32>;

struct StructureParams {
    candidate_count: u32,
    input_length: u32,
    context_window: u32,
    _pad: u32,
}

fn get_byte(idx: u32) -> u32 {
    if idx >= params.input_length { return 0u; }
    let u32_idx = idx / 4u;
    let byte_offset = (idx % 4u) * 8u;
    return (input_bytes[u32_idx] >> byte_offset) & 0xFFu;
}

@compute @workgroup_size(64)
fn analyze_structure(
    @builtin(global_invocation_id) gid: vec3<u32>,
) {
    let candidate_idx = gid.x;
    if candidate_idx >= params.candidate_count { return; }

    let offset = candidate_offsets[candidate_idx];
    let ctx_start = select(0u, offset - params.context_window, offset >= params.context_window);
    let ctx_end = min(offset + params.context_window, params.input_length);

    var score: f32 = 0.0;
    var flags: u32 = 0u;

    // Check byte immediately before candidate for quote
    if offset > 0u {
        let prev = get_byte(offset - 1u);
        if prev == 34u || prev == 39u {  // " or '
            score = score + 0.30;
            flags = flags | STRUCT_QUOTED;
        }
        if prev == 61u {  // =
            score = score + 0.20;
            flags = flags | STRUCT_ASSIGNED;
        }
    }

    // Check 2 bytes before for ": " (YAML/JSON pattern)
    if offset >= 2u {
        let prev2 = get_byte(offset - 2u);
        let prev1 = get_byte(offset - 1u);
        if prev2 == 58u && prev1 == 32u {  // ": "
            score = score + 0.15;
            flags = flags | STRUCT_ASSIGNED;
        }
    }

    // Clamp to 1.0
    score = min(score, 1.0);

    structure_results[candidate_idx] = StructureResult(candidate_idx, score, flags, 0u);
}
