// Fused histogram + Shannon entropy kernel
// Each workgroup processes one 64-byte chunk.
// 256 threads per workgroup × 64 bytes per chunk → 16 384 bytes per dispatch.
@group(0) @binding(0) var<storage, read>       input  : array<u32>;
@group(0) @binding(1) var<storage, read_write> output : array<f32>;

// Workgroup-local byte-frequency histogram (256 possible byte values).
var<workgroup> histogram : array<atomic<u32>, 256>;

@compute @workgroup_size(256)
fn compute_entropy(
    @builtin(global_invocation_id) gid : vec3<u32>,
    @builtin(local_invocation_id)  lid : vec3<u32>,
    @builtin(workgroup_id)         wid : vec3<u32>,
) {
    let global_wid : u32 = wid.y * 65535u + wid.x;
    let num_chunks: u32 = arrayLength(&output);
    if global_wid >= num_chunks {
        return;
    }

    // ── Phase 1: clear histogram slot owned by this thread ──────────────
    atomicStore(&histogram[lid.x], 0u);
    workgroupBarrier();

    // ── Phase 2: accumulate byte frequencies ────────────────────────────
    // Each 64-byte chunk occupies 16 u32 words.
    // Thread `lid.x` is responsible for byte index `lid.x % 64` within the
    // chunk, packed as a single byte inside the relevant u32 word.
    let chunk_word_base : u32 = global_wid * 16u;          // first word of this chunk
    let byte_in_chunk   : u32 = lid.x % 64u;          // which byte within chunk
    let word_offset     : u32 = byte_in_chunk / 4u;   // which u32 word holds it
    let byte_lane       : u32 = byte_in_chunk % 4u;   // which byte within u32

    let word_idx : u32 = chunk_word_base + word_offset;
    // Guard against reading past the end of the buffer.
    if lid.x < 64u {
        if word_idx < arrayLength(&input) {
            let packed  : u32 = input[word_idx];
            let byte_val: u32 = (packed >> (byte_lane * 8u)) & 0xFFu;
            atomicAdd(&histogram[byte_val], 1u);
        }
    }
    workgroupBarrier();

    // ── Phase 3: compute entropy (thread 0 only) ─────────────────────────
    if lid.x == 0u {
        var entropy : f32 = 0.0;
        for (var b : u32 = 0u; b < 256u; b = b + 1u) {
            let count : f32 = f32(atomicLoad(&histogram[b]));
            if count > 0.0 {
                let p : f32 = count / 64.0;
                entropy -= p * log2(p);
            }
        }
        output[global_wid] = entropy;
    }
}
