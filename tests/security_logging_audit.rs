use std::fs;

const FILES_TO_AUDIT: &[&str] = &["src/commands/wallet.rs", "src/commands/deploy.rs"];

#[test]
fn no_sensitive_patterns_are_emitted_at_info_level() {
    let patterns = [
        ("p::info(", "Secret Key"),
        ("p::info(", "secret_key"),
        ("p::info(", "plain_sk"),
        ("p::info(", "transaction_xdr"),
        ("p::info(", "signed_xdr"),
        ("p::info(", "XDR"),
    ];

    for path in FILES_TO_AUDIT {
        let contents =
            fs::read_to_string(path).unwrap_or_else(|_| panic!("Failed to read {}", path));
        for (prefix, sensitive) in patterns {
            for (index, line) in contents.lines().enumerate() {
                if line.contains(prefix) && line.contains(sensitive) {
                    panic!(
                        "Sensitive pattern found in {}:{}:\n  {}\n  contains both '{}' and '{}'",
                        path,
                        index + 1,
                        line.trim(),
                        prefix,
                        sensitive
                    );
                }
            }
        }
    }
}
