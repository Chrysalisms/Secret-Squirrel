// Stage 1: Shannon Entropy + Histogram kernel (fused)
//
// Each workgroup (256 threads) processes a 64-byte input chunk.
// Shared memory histogram accumulates byte frequencies.
// Final thread computes Shannon entropy: H = -sum(p_i * log2(p_i))
//
// Input buffer: flat byte array (packed as u32 for alignment)
// Output buffer: entropy value per 64-byte chunk (f32)

struct EntropyOutput {
    entropy: f32,
}

@group(0) @binding(0) var<storage, read> input_bytes: array<u32>;
@group(0) @binding(1) var<storage, read_write> output_entropy: array<f32>;
@group(0) @binding(2) var<uniform> params: EntropyParams;

struct EntropyParams {
    chunk_count: u32,
    chunk_size_bytes: u32,  // 64
    input_length: u32,
    _pad: u32,
}

// Workgroup shared memory for byte frequency histogram
var<workgroup> histogram: array<atomic<u32>, 256>;

@compute @workgroup_size(64)
fn compute_entropy(
    @builtin(workgroup_id) wg_id: vec3<u32>,
    @builtin(local_invocation_id) lid: vec3<u32>,
) {
    let chunk_idx = wg_id.x;
    let local_id = lid.x;

    // Initialize histogram slot for this thread (4 slots per thread for 256 total)
    for (var i = 0u; i < 4u; i = i + 1u) {
        atomicStore(&histogram[local_id * 4u + i], 0u);
    }
    workgroupBarrier();

    // Each thread processes 1 byte from the 64-byte chunk
    let byte_idx = chunk_idx * params.chunk_size_bytes + local_id;

    if byte_idx < params.input_length {
        // Extract byte from packed u32 array
        let u32_idx = byte_idx / 4u;
        let byte_offset = (byte_idx % 4u) * 8u;
        let byte_val = (input_bytes[u32_idx] >> byte_offset) & 0xFFu;

        // Increment histogram for this byte value
        atomicAdd(&histogram[byte_val], 1u);
    }

    workgroupBarrier();

    // Thread 0 computes entropy from histogram
    if local_id == 0u {
        var entropy: f32 = 0.0;
        let chunk_size_f = f32(params.chunk_size_bytes);

        for (var b = 0u; b < 256u; b = b + 1u) {
            let count = atomicLoad(&histogram[b]);
            if count > 0u {
                let p = f32(count) / chunk_size_f;
                entropy = entropy - p * log2(p);
            }
        }

        output_entropy[chunk_idx] = entropy;
    }
}
