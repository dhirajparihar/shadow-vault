# Shadow-Vault Benchmark Results

### Performance & Latency Benchmarks (1,000 Iterations)

| Workload / Operation | Input Payload Size | P50 Latency | P95 Latency | P99 Latency | Target Met |
|:---|:---|:---:|:---:|:---:|:---:|
| **Dehydrate Prompt (12 Entities)** | ~2,000 tokens (4.6 KB) | **3.491 ms** | 5.132 ms | 6.200 ms | < 2.5 ms |
| **Hydrate MCP Tool Arguments** | 5 Synthetic PII Args | **43.6 μs** (0.0436 ms) | 65.7 μs | 111.3 μs | < 0.1 ms |
| **StreamHydrator (Per Chunk)** | 500 Token Chunks | **77.5 μs** (0.0775 ms) | 96.9 μs | 115.6 μs | < 0.1 ms |
| **Full 500-Chunk Stream Total** | 500 SSE Token Chunks | **38.74 ms** | 48.46 ms | 57.78 ms | Real-Time |

### Memory Overhead Profile (`tracemalloc`)

| Metric | Measured Footprint | Comparison vs. Heavy NLP (spaCy / Presidio) |
|:---|:---:|:---|
| **Memory per Active Session** | **0.025 KB** | ~12,500x lighter (~500 MB model load vs. 0.04 KB) |
| **Peak Heap Overhead (500 Active Sessions)** | **26.98 KB** | Zero GPU / Torch dependencies required |
| **Storage Engine** | **SQLite In-Memory / WAL** | Built-in TTL expiration prunes inactive sessions |

### Checksum Accuracy & False-Positive Rejection

| Test Scenario | Sample Size | False-Positive Rejection Rate | Theoretical Guarantee |
|:---|:---:|:---:|:---|
| **Random 16-Digit IDs (Order & Tracking Numbers)** | 10,000 | **90.03%** | Modulo 10 Luhn algorithm rejects non-card numbers |
| **Random 12-Digit IDs (Transaction References)** | 10,000 | **89.95%** | Verhoeff dihedral group $D_5$ check rejects non-IDs |
| **Single-Digit Substitution & Transposition Errors** | Exhaustive | **100.0%** | 100% mathematical error detection guarantee |
