// Stage 3B: Literal Value Stream Analysis
//
// Analyzes the actual high-entropy string value for character class patterns
// that indicate specific credential types.
//
// Character class detection:
//   Pure hex (0-9a-fA-F)       → score 0.70
//   Base64 alphabet            → score 0.75
//   Mixed alnum+special        → score 0.85
//   UUID format                → score 0.65
//   JWT (3 base64 segs w/ .)   → score 0.95
//   AKIA prefix (AWS)          → score 0.95
//   ghp_/gho_ prefix (GitHub)  → score 0.95

struct LiteralResult {
    candidate_idx: u32,
    score: f32,
    char_class_flags: u32,
    detected_format: u32,  // 0=unknown, 1=hex, 2=base64, 3=mixed, 4=uuid, 5=jwt, 6=aws_key, 7=github_token
}

// Format codes
const FORMAT_UNKNOWN: u32 = 0u;
const FORMAT_HEX: u32 = 1u;
const FORMAT_BASE64: u32 = 2u;
const FORMAT_MIXED: u32 = 3u;
const FORMAT_UUID: u32 = 4u;
const FORMAT_JWT: u32 = 5u;
const FORMAT_AWS_KEY: u32 = 6u;
const FORMAT_GITHUB_TOKEN: u32 = 7u;

@group(0) @binding(0) var<storage, read> input_bytes: array<u32>;
@group(0) @binding(1) var<storage, read_write> literal_results: array<LiteralResult>;
@group(0) @binding(2) var<uniform> params: LiteralParams;

struct LiteralParams {
    candidate_count: u32,
    input_length: u32,
    _pad0: u32,
    _pad1: u32,
}

struct CandidateRef {
    offset: u32,
    length: u32,
}

@group(0) @binding(3) var<storage, read> candidate_refs: array<CandidateRef>;

fn get_byte(idx: u32) -> u32 {
    if idx >= params.input_length { return 0u; }
    let u32_idx = idx / 4u;
    let byte_offset = (idx % 4u) * 8u;
    return (input_bytes[u32_idx] >> byte_offset) & 0xFFu;
}

fn is_hex_char(b: u32) -> bool {
    return (b >= 48u && b <= 57u) ||   // 0-9
           (b >= 65u && b <= 70u) ||   // A-F
           (b >= 97u && b <= 102u);    // a-f
}

fn is_base64_char(b: u32) -> bool {
    return (b >= 48u && b <= 57u) ||    // 0-9
           (b >= 65u && b <= 90u) ||   // A-Z
           (b >= 97u && b <= 122u) ||  // a-z
           b == 43u || b == 47u ||     // + /
           b == 61u;                   // = (padding)
}

fn is_base64url_char(b: u32) -> bool {
    return (b >= 48u && b <= 57u) ||
           (b >= 65u && b <= 90u) ||
           (b >= 97u && b <= 122u) ||
           b == 45u || b == 95u;  // - _
}

@compute @workgroup_size(64)
fn analyze_literal(
    @builtin(global_invocation_id) gid: vec3<u32>,
) {
    let candidate_idx = gid.x;
    if candidate_idx >= params.candidate_count { return; }

    let ref_data = candidate_refs[candidate_idx];
    let offset = ref_data.offset;
    let length = ref_data.length;

    var hex_count: u32 = 0u;
    var base64_count: u32 = 0u;
    var dot_count: u32 = 0u;
    var dash_count: u32 = 0u;

    for (var i = 0u; i < length && i < 512u; i = i + 1u) {
        let b = get_byte(offset + i);
        if is_hex_char(b) { hex_count = hex_count + 1u; }
        if is_base64_char(b) { base64_count = base64_count + 1u; }
        if b == 46u { dot_count = dot_count + 1u; } // '.'
        if b == 45u { dash_count = dash_count + 1u; } // '-'
    }

    var score: f32 = 0.5;
    var format: u32 = FORMAT_UNKNOWN;

    // Determine character class
    let length_f = f32(length);
    if length > 0u {
        if f32(hex_count) / length_f > 0.95 {
            score = 0.70;
            format = FORMAT_HEX;
        } else if dot_count == 2u && length > 20u {
            // Likely JWT (3 base64url segments)
            score = 0.95;
            format = FORMAT_JWT;
        } else if f32(base64_count) / length_f > 0.90 {
            score = 0.75;
            format = FORMAT_BASE64;
        } else {
            score = 0.85;
            format = FORMAT_MIXED;
        }
    }

    literal_results[candidate_idx] = LiteralResult(candidate_idx, score, 0u, format);
}
