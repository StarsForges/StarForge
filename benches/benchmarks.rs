use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a mock TemplateEntry with the given name, used to benchmark
/// search / lookup code without touching the filesystem.
fn mock_template(name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "description": "Benchmark template for testing registry search performance",
        "version": "1.0.0",
        "source": format!("https://github.com/example/{}.git", name),
        "tags": ["soroban", "defi", "benchmark"],
        "author": "StarForge Bench",
        "downloads": 42,
        "verified": true,
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z"
    })
}

/// Build a registry JSON blob with `count` entries.
fn make_registry_json(count: usize) -> String {
    let templates: Vec<serde_json::Value> = (0..count)
        .map(|i| mock_template(&format!("template-{}", i)))
        .collect();
    serde_json::to_string(&serde_json::json!({ "templates": templates })).unwrap()
}

// ── 1. CLI argument parsing ───────────────────────────────────────────────────

/// Simulates the overhead of constructing and formatting a CLI invocation string.
/// Represents the argument tokenisation cost on every command run.
fn bench_cli_arg_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("cli_arg_parsing");
    group.measurement_time(Duration::from_secs(5));

    let sample_args = vec![
        vec!["starforge", "wallet", "create", "--name", "bench-wallet"],
        vec!["starforge", "template", "list"],
        vec![
            "starforge",
            "deploy",
            "--wasm",
            "contract.wasm",
            "--network",
            "testnet",
        ],
        vec![
            "starforge",
            "contract",
            "invoke",
            "--id",
            "ABC123",
            "--fn",
            "hello",
        ],
        vec![
            "starforge",
            "plugin",
            "install",
            "my-plugin",
            "--path",
            "./libmy.so",
        ],
    ];

    for args in &sample_args {
        let label = args[1..3].join("_");
        group.bench_function(&label, |b| {
            b.iter(|| {
                // Simulate tokenising and joining args as the CLI framework would.
                let joined: Vec<String> = black_box(args).iter().map(|s| s.to_string()).collect();
                black_box(joined);
            })
        });
    }

    group.finish();
}

// ── 2. Template registry operations ──────────────────────────────────────────

/// Benchmarks JSON deserialisation of the template registry at various sizes.
/// This mirrors what `starforge template list` does on startup.
fn bench_template_registry_deserialise(c: &mut Criterion) {
    let mut group = c.benchmark_group("template_registry_deserialise");
    group.measurement_time(Duration::from_secs(8));

    for count in [10usize, 50, 200, 1000] {
        let json = make_registry_json(count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &json, |b, json_str| {
            b.iter(|| {
                let v: serde_json::Value =
                    serde_json::from_str(black_box(json_str)).expect("valid JSON");
                black_box(v);
            })
        });
    }

    group.finish();
}

/// Benchmarks linear search through the registry — mirrors `starforge template search`.
fn bench_template_registry_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("template_registry_search");
    group.measurement_time(Duration::from_secs(6));

    for count in [10usize, 100, 500] {
        let templates: Vec<serde_json::Value> = (0..count)
            .map(|i| mock_template(&format!("template-{}", i)))
            .collect();

        // Search for a term that matches roughly half the entries.
        let query = "template-5";

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &templates, |b, tmpl| {
            b.iter(|| {
                let q = black_box(query).to_lowercase();
                let results: Vec<_> = tmpl
                    .iter()
                    .filter(|t| t["name"].as_str().unwrap_or("").to_lowercase().contains(&q))
                    .collect();
                black_box(results);
            })
        });
    }

    group.finish();
}

// ── 3. Wallet key generation (simulated) ─────────────────────────────────────

/// Benchmarks the cost of constructing a dummy Stellar-style wallet name and
/// address string, representative of the formatting overhead in wallet commands.
fn bench_wallet_entry_format(c: &mut Criterion) {
    let mut group = c.benchmark_group("wallet_entry_format");
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("format_wallet_kv", |b| {
        let name = "bench-wallet";
        let address = "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37";
        b.iter(|| {
            let s = format!("name={} address={}", black_box(name), black_box(address));
            black_box(s);
        })
    });

    // Simulate serialising a list of 100 wallet entries as JSON.
    group.bench_function("serialise_100_wallets", |b| {
        let wallets: Vec<serde_json::Value> = (0..100)
            .map(|i| {
                serde_json::json!({
                    "name": format!("wallet-{}", i),
                    "address": "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37",
                    "network": "testnet"
                })
            })
            .collect();

        b.iter(|| {
            let s = serde_json::to_string(black_box(&wallets)).unwrap();
            black_box(s);
        })
    });

    group.finish();
}

// ── 4. Profiler overhead ──────────────────────────────────────────────────────

/// Verifies the Profiler utility has acceptably low overhead so it doesn't
/// distort the commands that embed it.
fn bench_profiler_overhead(c: &mut Criterion) {
    use std::time::Instant;

    let mut group = c.benchmark_group("profiler_overhead");
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("mark_10_phases", |b| {
        b.iter(|| {
            let start = Instant::now();
            let mut marks: Vec<(String, Instant)> = Vec::with_capacity(10);
            for i in 0..10u32 {
                marks.push((format!("phase_{}", black_box(i)), Instant::now()));
            }
            // Compute phase durations (mirrors Profiler::points).
            let mut last = start;
            let mut durations = Vec::with_capacity(marks.len());
            for (label, at) in &marks {
                durations.push((label.clone(), at.duration_since(last)));
                last = *at;
            }
            black_box(durations);
        })
    });

    group.finish();
}

// ── 5. WASM byte processing ───────────────────────────────────────────────────

/// Simulates a scan over WASM bytes, mirroring the accumulator loop in
/// `starforge benchmark --wasm`.  Parameterised by payload size.
fn bench_wasm_byte_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasm_byte_scan");
    group.measurement_time(Duration::from_secs(8));

    for size_kb in [16usize, 64, 256, 1024] {
        let bytes: Vec<u8> = (0..(size_kb * 1024)).map(|i| (i & 0xff) as u8).collect();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &bytes,
            |b, data| {
                b.iter(|| {
                    let mut acc: u64 = 0;
                    for (i, byte) in black_box(data).iter().enumerate() {
                        acc = acc.wrapping_add(*byte as u64).wrapping_add(i as u64);
                    }
                    black_box(acc);
                })
            },
        );
    }

    group.finish();
}

// ── 6. Deployment preparation ─────────────────────────────────────────────────

/// Benchmarks constructing a deployment payload — the JSON body that would be
/// sent to a Stellar/Soroban node — at various argument sizes.
fn bench_deploy_payload_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("deploy_payload_build");
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("small_payload", |b| {
        b.iter(|| {
            let payload = serde_json::json!({
                "wasm_hash": black_box("aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900"),
                "network": "testnet",
                "source": "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37",
                "fee": 100u64,
            });
            black_box(payload);
        })
    });

    // Larger payload with constructor arguments.
    group.bench_function("large_payload_with_args", |b| {
        let constructor_args: Vec<serde_json::Value> = (0..32)
            .map(|i| serde_json::json!({ "type": "u64", "value": i }))
            .collect();
        b.iter(|| {
            let payload = serde_json::json!({
                "wasm_hash": "aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900",
                "network": "testnet",
                "source": "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37",
                "fee": 100u64,
                "constructor_args": black_box(&constructor_args),
            });
            black_box(payload);
        })
    });

    group.finish();
}

// ── 7. Legacy baseline (kept for regression comparison) ──────────────────────

fn bench_basic(c: &mut Criterion) {
    c.bench_function("simulate_ops_10k", |b| {
        b.iter(|| {
            let mut acc: u64 = 0;
            for i in 0..10_000u64 {
                acc = acc.wrapping_add(i & 0xff);
            }
            black_box(acc);
        })
    });
}

// ── Registration ──────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_basic,
    bench_cli_arg_parsing,
    bench_template_registry_deserialise,
    bench_template_registry_search,
    bench_wallet_entry_format,
    bench_profiler_overhead,
    bench_wasm_byte_scan,
    bench_deploy_payload_build,
);
criterion_main!(benches);
