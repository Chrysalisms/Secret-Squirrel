//! Triple-buffered GPU memory pool for Secret Squirrel's scan pipeline.
//!
//! [`BufferPool`] manages a set of staging buffers used to feed the GPU
//! entropy kernel.  While actual `wgpu` device buffers are created and owned
//! inside [`super::gpu`], the pool here provides the *host-side* staging
//! layer:
//!
//! - Under `#[cfg(feature = "gpu")]` it exposes helpers that produce
//!   byte slices ready to be written into `wgpu::Buffer`s.
//! - Under the CPU-only build it degrades gracefully to plain `Vec<u8>`
//!   allocations so the rest of the pipeline compiles unchanged.
//!
//! The "triple" in triple-buffered refers to rotating among three equal
//! slots so that:
//! - slot 0 — being read by GPU / being processed by CPU
//! - slot 1 — being filled by the I/O path
//! - slot 2 — idle / available for the next write
//!
//! This prevents stalls and keeps the GPU feed path saturated.

const NUM_SLOTS: usize = 3;

/// A CPU-side staging buffer slot.
#[derive(Debug)]
struct Slot {
    /// Raw byte data for this slot.
    data: Vec<u8>,
    /// How many valid bytes are currently in `data`.
    len: usize,
}

impl Slot {
    fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            len: 0,
        }
    }

    /// Write `src` into the slot, truncating if `src` exceeds capacity.
    /// Returns the number of bytes actually written.
    fn write(&mut self, src: &[u8]) -> usize {
        let n = src.len().min(self.data.len());
        self.data[..n].copy_from_slice(&src[..n]);
        self.len = n;
        n
    }

    /// Return the valid portion of this slot as a byte slice.
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Zero the slot contents (called after GPU upload to prevent leakage).
    fn clear(&mut self) {
        // Use zeroize-style explicit overwrite so the compiler cannot
        // optimise it away.
        for b in &mut self.data[..self.len] {
            // SAFETY: plain u8 write, no unsafe needed
            *b = 0;
        }
        self.len = 0;
    }
}

/// Triple-buffered host-side staging buffer pool.
///
/// # Example
/// ```
/// use secret_squirrel::engine::buffers::BufferPool;
///
/// let mut pool = BufferPool::with_capacity(1024);
/// let written = pool.write_slot(0, b"hello world");
/// assert_eq!(written, 11);
/// let s = pool.slot_as_slice(0);
/// assert_eq!(s, b"hello world");
/// ```
#[derive(Debug)]
pub struct BufferPool {
    /// Maximum bytes each slot can hold.
    pub capacity_bytes: u64,
    slots: [Slot; NUM_SLOTS],
    /// Index of the slot currently being consumed (0, 1, or 2).
    active: usize,
}

impl BufferPool {
    /// Create a new pool with `capacity_bytes` per slot.
    pub fn new(capacity_bytes: u64) -> Self {
        let cap = capacity_bytes as usize;
        Self {
            capacity_bytes,
            // `std::array::from_fn` is stable since Rust 1.63 — well within MSRV 1.75.
            slots: std::array::from_fn(|_| Slot::new(cap)),
            active: 0,
        }
    }

    /// Convenience constructor — allocates `n` bytes per slot.
    pub fn with_capacity(n: usize) -> Self {
        Self::new(n as u64)
    }

    /// Write `data` into slot `idx` (0–2).
    ///
    /// Returns the number of bytes actually written (may be less than
    /// `data.len()` if `data` exceeds the slot capacity).
    ///
    /// # Panics
    /// Panics if `idx >= 3`.
    pub fn write_slot(&mut self, idx: usize, data: &[u8]) -> usize {
        assert!(idx < NUM_SLOTS, "BufferPool: slot index {idx} out of range");
        self.slots[idx].write(data)
    }

    /// Return the valid data in slot `idx` as a byte slice.
    ///
    /// # Panics
    /// Panics if `idx >= 3`.
    pub fn slot_as_slice(&self, idx: usize) -> &[u8] {
        assert!(idx < NUM_SLOTS, "BufferPool: slot index {idx} out of range");
        self.slots[idx].as_slice()
    }

    /// Zero-out slot `idx` to prevent data leakage between scans.
    ///
    /// # Panics
    /// Panics if `idx >= 3`.
    pub fn clear_slot(&mut self, idx: usize) {
        assert!(idx < NUM_SLOTS, "BufferPool: slot index {idx} out of range");
        self.slots[idx].clear();
    }

    /// Zero all three slots.  Call after GPU upload or at session end.
    pub fn clear_all(&mut self) {
        for slot in &mut self.slots {
            slot.clear();
        }
    }

    /// Advance to the next slot in round-robin order.
    ///
    /// Returns the index of the newly-active slot.
    pub fn advance(&mut self) -> usize {
        self.active = (self.active + 1) % NUM_SLOTS;
        self.active
    }

    /// Return the index of the currently active slot.
    pub fn active_slot(&self) -> usize {
        self.active
    }

    /// Return the next slot index without advancing (peek).
    pub fn next_slot(&self) -> usize {
        (self.active + 1) % NUM_SLOTS
    }

    /// Total memory allocated across all slots (bytes).
    pub fn total_allocated(&self) -> u64 {
        self.capacity_bytes * NUM_SLOTS as u64
    }

    // ── wgpu integration helpers ──────────────────────────────────────────
    //
    // These are gated behind `#[cfg(feature = "gpu")]` because they expose
    // wgpu types.  The host-side `Slot` data is what gets written into a
    // `wgpu::Queue::write_buffer` call inside `gpu.rs`.

    /// Return a raw byte slice suitable for `wgpu::Queue::write_buffer`.
    ///
    /// The caller is responsible for ensuring that the GPU has finished
    /// reading the previous contents of the corresponding device buffer
    /// before calling this.
    #[cfg(feature = "gpu")]
    pub fn gpu_upload_slice(&self, idx: usize) -> &[u8] {
        self.slot_as_slice(idx)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pool_capacity() {
        let pool = BufferPool::new(1024);
        assert_eq!(pool.capacity_bytes, 1024);
        assert_eq!(pool.total_allocated(), 1024 * 3);
    }

    #[test]
    fn test_with_capacity() {
        let pool = BufferPool::with_capacity(512);
        assert_eq!(pool.capacity_bytes, 512);
    }

    #[test]
    fn test_write_and_read_slot() {
        let mut pool = BufferPool::with_capacity(64);
        let data = b"secret_key=AKIAIOSFODNN7EXAMPLE";
        let written = pool.write_slot(0, data);
        assert_eq!(written, data.len());
        assert_eq!(pool.slot_as_slice(0), data);
    }

    #[test]
    fn test_write_truncates_at_capacity() {
        let mut pool = BufferPool::with_capacity(8);
        let data = b"this_is_longer_than_8_bytes";
        let written = pool.write_slot(0, data);
        assert_eq!(written, 8);
        assert_eq!(pool.slot_as_slice(0), &data[..8]);
    }

    #[test]
    fn test_clear_slot_zeroes_data() {
        let mut pool = BufferPool::with_capacity(16);
        pool.write_slot(1, b"sensitive_data!!");
        pool.clear_slot(1);
        assert_eq!(pool.slot_as_slice(1), b"");
    }

    #[test]
    fn test_advance_rotates() {
        let mut pool = BufferPool::with_capacity(16);
        assert_eq!(pool.active_slot(), 0);
        assert_eq!(pool.advance(), 1);
        assert_eq!(pool.advance(), 2);
        assert_eq!(pool.advance(), 0); // wraps
    }

    #[test]
    fn test_next_slot_peek() {
        let mut pool = BufferPool::with_capacity(16);
        assert_eq!(pool.next_slot(), 1);
        pool.advance();
        assert_eq!(pool.next_slot(), 2);
    }

    #[test]
    fn test_clear_all() {
        let mut pool = BufferPool::with_capacity(16);
        pool.write_slot(0, b"aaaaaaaaaaaaaaaa");
        pool.write_slot(1, b"bbbbbbbbbbbbbbbb");
        pool.write_slot(2, b"cccccccccccccccc");
        pool.clear_all();
        for i in 0..3 {
            assert_eq!(pool.slot_as_slice(i), b"");
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn test_write_slot_oob_panics() {
        let mut pool = BufferPool::with_capacity(16);
        pool.write_slot(3, b"boom");
    }
}
