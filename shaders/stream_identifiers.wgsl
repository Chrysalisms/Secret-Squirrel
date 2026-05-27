// Stage 3A: Identifier Stream Extraction
//
// Extracts variable names and identifier tokens from the context
// surrounding each proximity candidate.
//
// Identifier scoring keywords (scored in CPU post-processing):
//   password, secret, token, key, api, auth, credential, private
//
// Output: identifier_score per candidate, plus packed identifier bytes

struct IdentifierResult {
    candidate_idx: u32,
    score: f32,
    identifier_offset: u32,  // offset into identifier_buffer
    identifier_length: u32,
}

@group(0) @binding(0) var<storage, read> input_bytes: array<u32>;
@group(0) @binding(1) var<storage, read> proximity_results: array<u32>;  // candidate offsets
@group(0) @binding(2) var<storage, read_write> identifier_results: array<IdentifierResult>;
@group(0) @binding(3) var<uniform> params: StreamParams;

struct StreamParams {
    candidate_count: u32,
    input_length: u32,
    context_window: u32,
    _pad: u32,
}

fn is_identifier_char(b: u32) -> bool {
    // a-z: 97-122, A-Z: 65-90, 0-9: 48-57, _: 95
    return (b >= 65u && b <= 90u) || (b >= 97u && b <= 122u) ||
           (b >= 48u && b <= 57u) || b == 95u;
}

fn get_byte(idx: u32) -> u32 {
    if idx >= params.input_length { return 0u; }
    let u32_idx = idx / 4u;
    let byte_offset = (idx % 4u) * 8u;
    return (input_bytes[u32_idx] >> byte_offset) & 0xFFu;
}

@compute @workgroup_size(64)
fn extract_identifiers(
    @builtin(global_invocation_id) gid: vec3<u32>,
) {
    let candidate_idx = gid.x;
    if candidate_idx >= params.candidate_count { return; }

    let candidate_offset = proximity_results[candidate_idx];
    let ctx_start = select(0u, candidate_offset - params.context_window, candidate_offset >= params.context_window);

    // Find the longest identifier sequence ending at or before candidate_offset
    var ident_end = candidate_offset;
    var ident_start = candidate_offset;

    // Scan backward to find identifier start
    var scan = candidate_offset;
    loop {
        if scan == 0u || scan <= ctx_start { break; }
        scan = scan - 1u;
        let b = get_byte(scan);
        if !is_identifier_char(b) { break; }
        ident_start = scan;
    }

    // Default score of 0.1 (no strong identifier found = neutral)
    var score: f32 = 0.1;

    identifier_results[candidate_idx] = IdentifierResult(
        candidate_idx,
        score,
        ident_start,
        ident_end - ident_start,
    );
}
