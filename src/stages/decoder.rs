use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use bytes::Bytes;
use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedVariant {
    pub data: Bytes,
    pub encoding_chain: Vec<String>,
}

/// Recursively decodes input bytes up to max_depth using Base64, Hex, and URL decoding.
pub fn deep_decode(input: &[u8], max_depth: usize) -> Vec<DecodedVariant> {
    let mut results = Vec::new();
    let mut queue = VecDeque::new();

    queue.push_back(DecodedVariant {
        data: Bytes::copy_from_slice(input),
        encoding_chain: Vec::new(),
    });

    while let Some(current) = queue.pop_front() {
        if current.encoding_chain.len() >= max_depth {
            continue;
        }

        // 1. Try Base64
        if is_base64_candidate(&current.data) {
            if let Ok(decoded) = BASE64_STD.decode(&current.data) {
                if !decoded.is_empty() && decoded != current.data {
                    let mut new_chain = current.encoding_chain.clone();
                    new_chain.push("Base64".to_string());
                    let new_variant = DecodedVariant {
                        data: Bytes::from(decoded),
                        encoding_chain: new_chain,
                    };
                    results.push(new_variant.clone());
                    queue.push_back(new_variant);
                }
            }
        }

        // 2. Try Hex
        if is_hex_candidate(&current.data) {
            if let Ok(decoded) = hex::decode(&current.data) {
                if !decoded.is_empty() && decoded != current.data {
                    let mut new_chain = current.encoding_chain.clone();
                    new_chain.push("Hex".to_string());
                    let new_variant = DecodedVariant {
                        data: Bytes::from(decoded),
                        encoding_chain: new_chain,
                    };
                    results.push(new_variant.clone());
                    queue.push_back(new_variant);
                }
            }
        }

        // 3. Try URL Decode
        if is_url_encoded_candidate(&current.data) {
            if let Some(decoded) = url_decode(&current.data) {
                if !decoded.is_empty() && decoded != current.data {
                    let mut new_chain = current.encoding_chain.clone();
                    new_chain.push("URL".to_string());
                    let new_variant = DecodedVariant {
                        data: Bytes::from(decoded),
                        encoding_chain: new_chain,
                    };
                    results.push(new_variant.clone());
                    queue.push_back(new_variant);
                }
            }
        }
    }

    results
}

fn is_base64_candidate(input: &[u8]) -> bool {
    if input.is_empty() || input.len() % 4 != 0 {
        return false;
    }
    input
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

fn is_hex_candidate(input: &[u8]) -> bool {
    if input.is_empty() || input.len() % 2 != 0 {
        return false;
    }
    input.iter().all(|&b| b.is_ascii_hexdigit())
}

fn is_url_encoded_candidate(input: &[u8]) -> bool {
    input.contains(&b'%')
}

fn url_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hex_str = std::str::from_utf8(&input[i + 1..i + 3]).ok()?;
            let byte = u8::from_str_radix(hex_str, 16).ok()?;
            out.push(byte);
            i += 3;
        } else if input[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deep_decode_shai_hulud() {
        let raw_secret = b"AKIAIOSFODNN7EXAMPLE";

        // 1. Base64
        let b64 = BASE64_STD.encode(raw_secret); // "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="

        // 2. URL Encode the Base64 (replace '=' with '%3D')
        let url_encoded = b64.replace("=", "%3D");

        // 3. Hex Encode the URL encoded string
        let hex_encoded = hex::encode(url_encoded);

        // 4. Base64 encode the hex
        let b64_2 = BASE64_STD.encode(hex_encoded);

        // 5. URL Encode again
        let final_payload = b64_2.replace("=", "%3D");

        let variants = deep_decode(final_payload.as_bytes(), 5);

        // Verify we found the original secret
        let found = variants.iter().find(|v| v.data.as_ref() == raw_secret);
        assert!(found.is_some(), "Should find original secret");

        let found_variant = found.unwrap();
        assert_eq!(
            found_variant.encoding_chain,
            vec!["Base64", "Hex", "URL", "Base64"]
        );
    }
}
