// block.hpp
// A single block in the evidence blockchain. Each block bundles one or more
// EvidenceRecords, commits to them via a Merkle root, links to the previous
// block's hash, and is "mined" with a simplified Proof-of-Work so that
// retroactively altering a block requires redoing the work for every block
// after it (standard blockchain tamper-evidence property).
#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include "evidence.hpp"
#include "merkle_tree.hpp"
#include "sha256_util.hpp"

namespace vault {

class Block {
public:
    uint64_t index = 0;
    std::string timestamp;
    std::string previousHash;
    std::string merkleRoot;
    std::vector<EvidenceRecord> records;
    uint64_t nonce = 0;
    uint32_t difficulty = 0;
    std::string hash;

    Block() = default;

    Block(uint64_t idx, std::string prevHash, std::vector<EvidenceRecord> recs)
        : index(idx),
          timestamp(nowTimestamp()),
          previousHash(std::move(prevHash)),
          records(std::move(recs)) {
        merkleRoot = computeMerkleRoot();
    }

    std::string computeMerkleRoot() const {
        std::vector<std::string> leafHashes;
        leafHashes.reserve(records.size());
        for (const auto& r : records) leafHashes.push_back(r.fileHash);
        MerkleTree tree(leafHashes);
        return tree.getRoot();
    }

    // The data that gets hashed to produce this block's identity. Includes
    // everything except `hash` itself, so any change to any field (including
    // a swapped evidence record, which changes merkleRoot) changes the hash.
    std::string headerString() const {
        std::ostringstream oss;
        oss << index << '|' << timestamp << '|' << previousHash << '|'
            << merkleRoot << '|' << nonce << '|' << difficulty;
        return oss.str();
    }

    std::string computeHash() const { return Sha256::hashString(headerString()); }

    // Simplified Proof-of-Work: find a nonce such that the resulting hash
    // has `difficulty` leading zero hex characters. This is intentionally
    // lightweight (difficulty 4-6) so it demonstrates the consensus concept
    // without making the CLI slow to use.
    void mine(uint32_t targetDifficulty) {
        difficulty = targetDifficulty;
        const std::string prefix(difficulty, '0');
        nonce = 0;
        std::string candidate = computeHash();
        while (candidate.compare(0, difficulty, prefix) != 0) {
            ++nonce;
            candidate = computeHash();
        }
        hash = candidate;
    }

    // Re-derive the merkle root + hash from current field contents, WITHOUT
    // re-mining. Used by the tamper detector to see what the hash *should*
    // be if nothing had been altered after the fact (vs. what is stored).
    std::string recomputeExpectedHash() const {
        std::string recomputedMerkle = computeMerkleRoot();
        std::ostringstream oss;
        oss << index << '|' << timestamp << '|' << previousHash << '|'
            << recomputedMerkle << '|' << nonce << '|' << difficulty;
        return Sha256::hashString(oss.str());
    }

    bool satisfiesDifficulty() const {
        const std::string prefix(difficulty, '0');
        return hash.compare(0, difficulty, prefix) == 0;
    }

    json toJson() const {
        json recs = json::array();
        for (const auto& r : records) recs.push_back(r.toJson());
        return json{{"index", index},
                     {"timestamp", timestamp},
                     {"previousHash", previousHash},
                     {"merkleRoot", merkleRoot},
                     {"records", recs},
                     {"nonce", nonce},
                     {"difficulty", difficulty},
                     {"hash", hash}};
    }

    static Block fromJson(const json& j) {
        Block b;
        b.index = j.at("index").get<uint64_t>();
        b.timestamp = j.at("timestamp").get<std::string>();
        b.previousHash = j.at("previousHash").get<std::string>();
        b.merkleRoot = j.at("merkleRoot").get<std::string>();
        for (const auto& r : j.at("records")) b.records.push_back(EvidenceRecord::fromJson(r));
        b.nonce = j.at("nonce").get<uint64_t>();
        b.difficulty = j.at("difficulty").get<uint32_t>();
        b.hash = j.at("hash").get<std::string>();
        return b;
    }
};

} // namespace vault
