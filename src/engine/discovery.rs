use crate::engine::cpu::CpuEngine;
use crate::types::DiscoveryCandidate;

#[derive(Debug, Clone, Default)]
pub struct DiscoveryStats {
    pub discovered_candidates: usize,
    pub typed_candidates: usize,
    pub multiline_candidates: usize,
}

#[derive(Debug, Clone, Default)]
pub struct CandidateBus {
    pub candidates: Vec<DiscoveryCandidate>,
    pub stats: DiscoveryStats,
}

impl CandidateBus {
    pub fn discover(cpu: &CpuEngine, data: &[u8], path_hint: Option<&str>) -> Self {
        let candidates = cpu.discover_candidates(data, path_hint);
        let stats = DiscoveryStats {
            discovered_candidates: candidates.len(),
            typed_candidates: candidates.iter().filter(|c| c.evidence.typed).count(),
            multiline_candidates: candidates.iter().filter(|c| c.evidence.multiline).count(),
        };
        Self { candidates, stats }
    }
}
