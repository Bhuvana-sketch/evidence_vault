// blockchain.hpp
// The evidence blockchain itself: a hash-linked, PoW-mined sequence of
// blocks, each holding one or more EvidenceRecords. Provides:
//   - addEvidenceBlock(): ingest new evidence, hash it, mine a block
//   - validateChain(): walk the whole chain checking hash links + PoW
//   - detectTampering(): re-hash every evidence file currently on disk and
//     compare against the hash stored at ingestion time
//   - generateIntegrityReport(): human-readable summary combining both
#pragma once

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "block.hpp"
#include "evidence.hpp"
#include "sha256_util.hpp"

namespace vault {

struct ChainLinkIssue {
    uint64_t blockIndex;
    std::string description;
};

struct TamperFinding {
    std::string evidenceId;
    std::string fileName;
    uint64_t blockIndex;
    std::string storedHash;
    std::string currentHash;   // empty if file missing
    bool fileMissing = false;
    bool tampered = false;     // storedHash != currentHash (and file present)
};

struct ValidationReport {
    bool chainIntact = true;
    std::vector<ChainLinkIssue> brokenLinks;      // hash-link / PoW problems
    std::vector<TamperFinding> tamperFindings;    // evidence-level tampering
    uint64_t firstAffectedBlock = 0;              // 0 if none
    bool anyIssues() const {
        return !brokenLinks.empty() ||
               std::any_of(tamperFindings.begin(), tamperFindings.end(),
                            [](const TamperFinding& t) { return t.tampered || t.fileMissing; });
    }
};

class Blockchain {
public:
    explicit Blockchain(uint32_t difficulty = 4) : difficulty_(difficulty) {
        createGenesisBlock();
    }

    uint32_t difficulty() const { return difficulty_; }
    void setDifficulty(uint32_t d) { difficulty_ = d; }

    const std::vector<Block>& blocks() const { return chain_; }

    // Ingest a new evidence file: compute its hash, build a custody-logged
    // EvidenceRecord, wrap it in a new block, and mine that block onto the
    // chain. Returns the evidenceId assigned.
    std::string addEvidence(const std::string& filePath, const std::string& actor,
                             const std::string& description = "") {
        std::string hash = Sha256::hashFile(filePath);
        std::size_t size = fileSize(filePath);

        EvidenceRecord rec;
        rec.evidenceId = nextEvidenceId();
        rec.originalPath = filePath;
        rec.fileName = basename(filePath);
        rec.fileHash = hash;
        rec.fileSizeBytes = size;
        rec.ingestedAt = nowTimestamp();
        rec.description = description;
        rec.addCustodyEntry(CustodyAction::CREATED, actor,
                             "Evidence ingested and hash committed to chain.");

        std::vector<EvidenceRecord> recs{rec};
        Block block(static_cast<uint64_t>(chain_.size()), chain_.back().hash, recs);
        block.mine(difficulty_);
        chain_.push_back(block);
        return rec.evidenceId;
    }

    // Append a custody event (review/transfer/archive) to an existing
    // evidence record. NOTE: because blocks are hash-chained and mined,
    // amending history requires re-mining this block and every block after
    // it -- exactly like a real blockchain. This models a *legitimate*
    // custody update (re-mined honestly), as opposed to tampering (which
    // the tamper simulator performs WITHOUT re-mining, so it's detectable).
    bool addCustodyEvent(const std::string& evidenceId, CustodyAction action,
                          const std::string& actor, const std::string& notes = "") {
        for (std::size_t i = 1; i < chain_.size(); ++i) {
            for (auto& rec : chain_[i].records) {
                if (rec.evidenceId == evidenceId) {
                    rec.addCustodyEntry(action, actor, notes);
                    remineFrom(i);
                    return true;
                }
            }
        }
        return false;
    }

    std::optional<EvidenceRecord> findEvidence(const std::string& evidenceId) const {
        for (const auto& block : chain_) {
            for (const auto& rec : block.records) {
                if (rec.evidenceId == evidenceId) return rec;
            }
        }
        return std::nullopt;
    }

    // --- Chain structural validation -----------------------------------
    // Walks block-to-block checking: (1) previousHash linkage, (2) stored
    // hash matches a from-scratch recomputation of the header, (3) PoW
    // difficulty target is satisfied. Any block that fails is reported,
    // and `firstAffectedBlock` marks where the chain first breaks (every
    // block after that point is considered suspect too, since a real
    // verifier can no longer trust the linkage from there onward).
    ValidationReport validateChain() const {
        ValidationReport report;
        for (std::size_t i = 0; i < chain_.size(); ++i) {
            const Block& b = chain_[i];
            std::vector<std::string> problems;

            if (i > 0 && b.previousHash != chain_[i - 1].hash) {
                problems.push_back("previousHash does not match prior block's hash");
            }
            std::string expected = b.recomputeExpectedHash();
            // recomputeExpectedHash uses the *stored* nonce; if records were
            // edited post-mining, the merkle root (and thus hash) changes
            // even though nonce/difficulty didn't, which is exactly the
            // tamper signal we want.
            if (i == 0) {
                // genesis block isn't mined against difficulty; just check
                // internal consistency of its stored hash.
                if (b.hash != expected) problems.push_back("stored hash does not match recomputed hash (data altered)");
            } else {
                if (b.hash != expected) {
                    problems.push_back("stored hash does not match recomputed hash (data altered)");
                }
                if (!b.satisfiesDifficulty()) {
                    problems.push_back("block hash does not satisfy proof-of-work difficulty");
                }
            }

            if (!problems.empty()) {
                report.chainIntact = false;
                if (report.firstAffectedBlock == 0) report.firstAffectedBlock = b.index;
                std::ostringstream oss;
                for (std::size_t p = 0; p < problems.size(); ++p) {
                    if (p) oss << "; ";
                    oss << problems[p];
                }
                report.brokenLinks.push_back({b.index, oss.str()});
            }
        }
        return report;
    }

    // --- Evidence-level tamper detection --------------------------------
    // For every evidence record on the chain, re-hash the file currently
    // on disk (at its recorded originalPath) and compare to the hash that
    // was committed at ingestion time. This catches tampering with the
    // *source file itself*, independent of whether the chain's internal
    // links are intact (e.g. someone edited the evidence file but didn't
    // touch the blockchain at all).
    std::vector<TamperFinding> detectFileTampering() const {
        std::vector<TamperFinding> findings;
        for (const auto& block : chain_) {
            for (const auto& rec : block.records) {
                TamperFinding f;
                f.evidenceId = rec.evidenceId;
                f.fileName = rec.fileName;
                f.blockIndex = block.index;
                f.storedHash = rec.fileHash;

                std::ifstream test(rec.originalPath, std::ios::binary);
                if (!test.good()) {
                    f.fileMissing = true;
                    f.tampered = true;
                } else {
                    f.currentHash = Sha256::hashFile(rec.originalPath);
                    f.tampered = (f.currentHash != f.storedHash);
                }
                findings.push_back(f);
            }
        }
        return findings;
    }

    // Combines structural chain validation with file-level tamper checks.
    ValidationReport generateIntegrityReport() const {
        ValidationReport report = validateChain();
        report.tamperFindings = detectFileTampering();
        return report;
    }

    // --- Tamper simulation ----------------------------------------------
    // Deliberately corrupts data WITHOUT re-mining, to demonstrate that the
    // system detects it. Two modes:
    //   mutateEvidenceFile(): rewrites bytes of the evidence file on disk,
    //     causing a file-hash mismatch (detected by detectFileTampering).
    //   mutateBlockRecord(): directly edits the fileHash stored in a block
    //     (simulating an attacker editing the ledger itself), causing a
    //     block-hash / merkle-root mismatch (detected by validateChain).
    bool simulateFileTamper(const std::string& evidenceId, const std::string& injectedText) {
        auto rec = findEvidence(evidenceId);
        if (!rec) return false;
        std::ofstream out(rec->originalPath, std::ios::binary | std::ios::app);
        if (!out.good()) return false;
        out << "\n[TAMPERED] " << injectedText << "\n";
        return true;
    }

    bool simulateLedgerTamper(const std::string& evidenceId, const std::string& fakeHash) {
        for (auto& block : chain_) {
            for (auto& rec : block.records) {
                if (rec.evidenceId == evidenceId) {
                    rec.fileHash = fakeHash; // corrupt the ledger directly, no re-mine
                    return true;
                }
            }
        }
        return false;
    }

    // --- Persistence helpers used by chain_io / sqlite_store ------------
    void replaceChain(std::vector<Block> newChain) {
        chain_ = std::move(newChain);
        syncEvidenceCounter();
    }
    uint64_t nextIndex() const { return static_cast<uint64_t>(chain_.size()); }

private:
    std::vector<Block> chain_;
    uint32_t difficulty_;
    uint64_t evidenceCounter_ = 0;

    void createGenesisBlock() {
        Block genesis;
        genesis.index = 0;
        genesis.timestamp = nowTimestamp();
        genesis.previousHash = std::string(64, '0');
        genesis.merkleRoot = Sha256::hashString("GENESIS");
        genesis.nonce = 0;
        genesis.difficulty = 0;
        genesis.hash = genesis.recomputeExpectedHash();
        chain_.push_back(genesis);
    }

    std::string nextEvidenceId() {
        ++evidenceCounter_;
        std::ostringstream oss;
        oss << "EVD-" << std::setw(4) << std::setfill('0') << evidenceCounter_;
        return oss.str();
    }

    // Re-mine block `fromIndex` and every block after it, so that a
    // legitimate edit (e.g. adding a custody entry) keeps the chain valid.
    void remineFrom(std::size_t fromIndex) {
        for (std::size_t i = fromIndex; i < chain_.size(); ++i) {
            chain_[i].previousHash = chain_[i - 1].hash;
            chain_[i].merkleRoot = chain_[i].computeMerkleRoot();
            if (i == 0) {
                chain_[i].hash = chain_[i].recomputeExpectedHash();
            } else {
                chain_[i].mine(difficulty_);
            }
        }
    }

    static std::size_t fileSize(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.good()) return 0;
        return static_cast<std::size_t>(f.tellg());
    }

    // After loading a chain from disk, make sure the next generated
    // evidence ID continues after the highest one already present, so IDs
    // never collide with previously ingested evidence.
    void syncEvidenceCounter() {
        uint64_t maxSeen = 0;
        for (const auto& block : chain_) {
            for (const auto& rec : block.records) {
                auto pos = rec.evidenceId.find_last_of('-');
                if (pos == std::string::npos) continue;
                try {
                    uint64_t n = std::stoull(rec.evidenceId.substr(pos + 1));
                    maxSeen = std::max(maxSeen, n);
                } catch (...) {
                    // non-numeric suffix, ignore
                }
            }
        }
        evidenceCounter_ = maxSeen;
    }

    static std::string basename(const std::string& path) {
        auto pos = path.find_last_of("/\\");
        return pos == std::string::npos ? path : path.substr(pos + 1);
    }
};

} // namespace vault
