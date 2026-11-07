# 🔐 Digital Evidence Integrity Vault — Blockchain (C++17)

A blockchain-based system that detects tampering of digital evidence
(logs, files, API records, configuration files) by committing each file's
SHA-256 hash to a hash-linked, proof-of-work-mined chain, then re-verifying
both the chain structure and the evidence files on demand.

## Architecture

```
include/
  sha256_util.hpp   SHA-256 hashing (OpenSSL EVP) for strings and streamed files
  merkle_tree.hpp    Binary Merkle tree + per-leaf inclusion proofs
  evidence.hpp       EvidenceRecord + CustodyEntry (chain-of-custody) data model
  block.hpp          Block: header, Merkle root, nonce, proof-of-work mining
  blockchain.hpp     Blockchain: ingest, custody updates, validation, tamper
                      detection, tamper SIMULATION
  chain_io.hpp        JSON file persistence (save/load the whole chain)
  sqlite_store.hpp    SQLite persistence (queryable blocks + evidence index)
  report.hpp          Human-readable integrity report (console + file)
src/
  main.cpp             Menu-driven CLI tying it all together
tests/
  demo_test.cpp        Non-interactive, asserting end-to-end walkthrough
data/                  chain.json / vault.db persisted here
evidence_files/        Sample evidence files used by the demo
reports/                Generated integrity reports (timestamped .txt)
```

### How tamper-evidence actually works here

1. **Per-file hash.** Every evidence file's SHA-256 is computed at ingestion
   and stored in an `EvidenceRecord` inside a `Block`.
2. **Merkle root.** All record hashes in a block are combined into a Merkle
   root, so a single block can efficiently hold (and later verify) many
   evidence records without rehashing everything.
3. **Block hash + chain link.** Each block's hash commits to its index,
   timestamp, `previousHash`, Merkle root, nonce, and difficulty. Each block
   stores the previous block's hash, forming the chain.
4. **Proof of Work.** Each block (except genesis) is "mined": the nonce is
   incremented until the block hash has N leading hex zeros (difficulty).
   This means retroactively editing a block requires redoing the PoW for
   that block *and every block after it* — the standard blockchain
   tamper-evidence guarantee.
5. **Two independent tamper checks** run together as the integrity report:
   - **Chain structural validation** — recomputes every block's hash from
     its current field values and PoW target; a mismatch flags exactly
     which block was altered and marks every block after it suspect.
   - **File tamper detection** — rehashes the evidence file currently on
     disk and compares it to the hash committed at ingestion time; this
     catches someone editing the *source file* directly, even if they never
     touch the ledger.
6. **Chain of custody.** Legitimate updates (review, transfer, archival) are
   appended as `CustodyEntry` records and the affected block (and everything
   after it) is honestly **re-mined**, so legitimate history changes stay
   valid. The tamper *simulator*, by contrast, edits data **without**
   re-mining — which is exactly what makes it detectable.

## Build

Requires a C++17 compiler, OpenSSL dev headers, and SQLite3 dev headers.

```bash
# Debian/Ubuntu
apt-get install -y libssl-dev libsqlite3-dev

make            # builds ./vault (interactive CLI)
make demo       # builds and runs ./demo_test (scripted end-to-end demo)
```

## Run the interactive CLI

```bash
./vault
```

Menu options cover: ingesting evidence (hash + mine a block), listing
records, viewing/adding chain-of-custody events, validating the chain and
generating an integrity report, viewing raw block details, **two tamper
simulation modes**, verifying a record via its Merkle proof, and saving /
loading the chain (JSON + SQLite).

### The two tamper simulations

- **Option 7 — File tamper:** appends bytes to the evidence file on disk
  *without* touching the ledger. Caught by the file tamper check (hash
  mismatch on that specific record).
- **Option 8 — Ledger tamper:** overwrites a record's stored hash directly
  inside a block, without re-mining. Caught by chain structural validation
  (the block's stored hash no longer matches a recomputation, and/or the
  PoW target is no longer satisfied) — pinpointing the first affected block.

Run option 5 after either simulation to see the automated integrity report
identify exactly which evidence record(s) were compromised.

## Run the scripted demo / test

```bash
make demo
```

This ingests three sample evidence files, logs custody events, validates a
clean chain (asserts PASS), runs both tamper simulations, validates again
(asserts the integrity report catches both — by evidence ID and by block
index), and round-trips persistence through both JSON and SQLite (asserting
the reloaded chain still reports the same tampering). It's also been run
clean under `-fsanitize=address,undefined`.

## Tech stack

C++17 · STL (vectors, maps, optional) · OpenSSL EVP (SHA-256) · SQLite3 C
API · nlohmann/json (single-header) · Make
