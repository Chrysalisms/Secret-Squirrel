use bytes::Bytes;
use secret_squirrel::config::{PipelineConfig, ScoringConfig};
use secret_squirrel::rules::compiler::compile_rules;
use secret_squirrel::rules::parser::parse_squirrel_config;
use secret_squirrel::scoring::fusion::FusionEngine;
use secret_squirrel::stages::entropy::EntropyGate;
use secret_squirrel::stages::pattern::PatternVerifier;
use secret_squirrel::stages::proximity::ProximityDetector;
use secret_squirrel::stages::tristream::TriStreamDecomposer;

#[test]
fn test_missing_key() {
    let rules_toml = std::fs::read_to_string("rules/generic/generic_catchall.toml").unwrap();
    let rules = parse_squirrel_config(&rules_toml).unwrap();
    let compiled = compile_rules(rules).unwrap();

    let verifier = PatternVerifier::new(&compiled).unwrap();
    let cfg = PipelineConfig::default();
    let eg = EntropyGate::new(&cfg);
    let pd = ProximityDetector::new(&cfg);
    let td = TriStreamDecomposer::new();
    let fe = FusionEngine::new(&ScoringConfig::default());

    let input = Bytes::from(
        "    Key = 7331f07936b4d50d37bdcec33d25082737cf45fec53cf4541fecfd27e8588ffa   ",
    );
    let candidates = eg.filter(&input);
    println!("Candidates: {:?}", candidates);

    let proximity_matches = pd.filter(candidates, &input);
    println!("Proximity Matches: {:?}", proximity_matches);

    let tri = td.decompose(proximity_matches);
    println!("TriStream: {:?}", tri);

    let pattern_matches = verifier.verify(tri);
    println!("Pattern Matches: {:?}", pattern_matches);

    for pm in pattern_matches {
        let score = fe.compute(
            &pm,
            0.5,
            None,
            None,
            &secret_squirrel::types::FragmentMetadata {
                path: "test".to_string(),
                source_type: secret_squirrel::types::SourceType::Directory,
                size: 100,
                attributes: std::collections::HashMap::new(),
            },
        );
        println!("Score: {:?}", score);
    }
}
