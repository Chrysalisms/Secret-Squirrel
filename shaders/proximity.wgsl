// Stage 2: Semantic Proximity Detection Kernel
//
// For each entropy candidate, scan the surrounding 256-byte context
// for patterns that indicate a credential assignment context.
//
// Pattern scoring:
//   = "   or ='  → Assignment (+0.35)
//   : "   or :'  → JSON/YAML key (+0.25)
//   export      → Shell export (+0.25)
//   ENV         → Docker ENV (+0.20)
//   Bearer      → HTTP header (+0.30)
//   keyword match (password/secret/token/key) → +0.20
//
// Output: proximity_score per candidate (f32, 0.0-1.0)

struct Candidate {
    offset: u32,
    length: u32,
    entropy: f32,
    _pad: u32,
}

struct ProximityResult {
    candidate_idx: u32,
    score: f32,
    pattern_flags: u32,  // bitmask of matched patterns
    _pad: u32,
}

// Pattern flag bitmask values
const PATTERN_ASSIGNMENT: u32 = 1u;
const PATTERN_JSON_KEY: u32 = 2u;
const PATTERN_EXPORT: u32 = 4u;
const PATTERN_DOCKER_ENV: u32 = 8u;
const PATTERN_HTTP_HEADER: u32 = 16u;
const PATTERN_KEYWORD: u32 = 32u;

@group(0) @binding(0) var<storage, read> input_bytes: array<u32>;
@group(0) @binding(1) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(2) var<storage, read_write> results: array<ProximityResult>;
@group(0) @binding(3) var<uniform> params: ProximityParams;

struct ProximityParams {
    candidate_count: u32,
    input_length: u32,
    context_window: u32,  // 256 bytes either side
    _pad: u32,
}

fn get_byte(idx: u32) -> u32 {
    if idx >= params.input_length { return 0u; }
    let u32_idx = idx / 4u;
    let byte_offset = (idx % 4u) * 8u;
    return (input_bytes[u32_idx] >> byte_offset) & 0xFFu;
}

// Check for 2-byte pattern starting at position
fn matches_2(pos: u32, b0: u32, b1: u32) -> bool {
    return get_byte(pos) == b0 && get_byte(pos + 1u) == b1;
}

// ASCII codes for pattern matching
const EQ: u32 = 61u;    // '='
const DQUOTE: u32 = 34u; // '"'
const SQUOTE: u32 = 39u; // '\''
const COLON: u32 = 58u;  // ':'
const SPACE: u32 = 32u;  // ' '

@compute @workgroup_size(64)
fn detect_proximity(
    @builtin(global_invocation_id) gid: vec3<u32>,
) {
    let candidate_idx = gid.x;
    if candidate_idx >= params.candidate_count { return; }

    let candidate = candidates[candidate_idx];
    let ctx_start = select(0u, candidate.offset - params.context_window, candidate.offset >= params.context_window);
    let ctx_end = min(candidate.offset + candidate.length + params.context_window, params.input_length);

    var score: f32 = 0.0;
    var flags: u32 = 0u;

    // Scan context window for patterns
    for (var i = ctx_start; i < ctx_end; i = i + 1u) {
        let b = get_byte(i);

        // =" pattern (assignment with double quote)
        if b == EQ && (get_byte(i + 1u) == DQUOTE || get_byte(i + 1u) == SQUOTE) {
            score = score + 0.35;
            flags = flags | PATTERN_ASSIGNMENT;
        }

        // :" pattern (JSON/YAML key)
        if b == COLON && get_byte(i + 1u) == SPACE && get_byte(i + 2u) == DQUOTE {
            score = score + 0.25;
            flags = flags | PATTERN_JSON_KEY;
        }
    }

    // Clamp score to 1.0
    score = min(score, 1.0);

    results[candidate_idx] = ProximityResult(candidate_idx, score, flags, 0u);
}
