// Markov chain randomness scorer kernel.
// Each workgroup processes one candidate string to compute its Markov randomness score.
//
// Bindings:
// 0: input  — raw bytes packed as u32
// 1: table  — the 64x64x64 f32 log-probability table (262,144 elements)
// 2: output — one f32 score per candidate
// 3: metadata - offsets and lengths for each candidate: [offset0, len0, offset1, len1, ...]

@group(0) @binding(0) var<storage, read>       input    : array<u32>;
@group(0) @binding(1) var<storage, read>       table    : array<f32>;
@group(0) @binding(2) var<storage, read_write> output   : array<f32>;
@group(0) @binding(3) var<storage, read>       metadata : array<u32>;

// 64-char alphabet mapping. We can use a simple lookup function for the byte to alphabet index.
// 0-25: a-z
// 26-51: A-Z
// 52-61: 0-9
// 62: _
// 63: -
// >63: invalid
fn get_alphabet_index(b: u32) -> u32 {
    if (b >= 97u && b <= 122u) { return b - 97u; }        // a-z -> 0-25
    if (b >= 65u && b <= 90u)  { return b - 65u + 26u; }  // A-Z -> 26-51
    if (b >= 48u && b <= 57u)  { return b - 48u + 52u; }  // 0-9 -> 52-61
    if (b == 95u) { return 62u; }                         // _   -> 62
    if (b == 45u) { return 63u; }                         // -   -> 63
    return 255u; // Invalid
}

fn get_byte(offset: u32) -> u32 {
    let word_idx = offset / 4u;
    let byte_lane = offset % 4u;
    let packed = input[word_idx];
    return (packed >> (byte_lane * 8u)) & 0xFFu;
}

@compute @workgroup_size(1)
fn compute_markov(
    @builtin(global_invocation_id) gid : vec3<u32>,
) {
    let cand_idx = gid.x;
    let offset_idx = cand_idx * 2u;
    let start_offset = metadata[offset_idx];
    let length = metadata[offset_idx + 1u];
    
    if (length == 0u) {
        output[cand_idx] = 0.0;
        return;
    }

    var total_log_p : f32 = 0.0;
    var count : u32 = 0u;

    // Buffer to hold the last 3 valid indices.
    var window : array<u32, 3>;
    var valid_chars : u32 = 0u;

    for (var i : u32 = 0u; i < length; i = i + 1u) {
        let b = get_byte(start_offset + i);
        let alpha_idx = get_alphabet_index(b);
        
        if (alpha_idx != 255u) {
            window[0] = window[1];
            window[1] = window[2];
            window[2] = alpha_idx;
            valid_chars = valid_chars + 1u;
            
            if (valid_chars >= 3u) {
                let table_idx = window[0] * 4096u + window[1] * 64u + window[2];
                total_log_p = total_log_p + table[table_idx];
                count = count + 1u;
            }
        }
    }

    if (count == 0u) {
        output[cand_idx] = 0.0;
        return;
    }

    let avg_log_p = total_log_p / f32(count);
    
    // Normalize logic (score_natural, score_random bounds provided by uniforms in a real impl,
    // here we hardcode the heuristic bounds for simplicity, or we can just return avg_log_p and normalize on CPU).
    // Let's just output avg_log_p and let the CPU normalize, or we can use the default -4.0, -14.0 bounds.
    let score_natural : f32 = -4.0;
    let score_random : f32 = -14.0;
    let range = score_natural - score_random;
    
    var normalized = (score_natural - avg_log_p) / range;
    if (normalized < 0.0) { normalized = 0.0; }
    if (normalized > 1.0) { normalized = 1.0; }
    
    output[cand_idx] = normalized;
}
