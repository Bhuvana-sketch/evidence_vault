// merkle_tree.hpp
// Classic binary Merkle tree over a list of leaf hashes (one per evidence
// record in a block). Odd leaf counts are handled by duplicating the last
// leaf at each level (the common Bitcoin-style convention).
//
// Exposes:
//   - getRoot(): the Merkle root for the whole leaf set
//   - getProof(leafIndex): sibling hashes needed to recompute the root from
//                           a single leaf, so one evidence record can be
//                           verified without rehashing every other record.
//   - verifyProof(...): static helper to check a proof against a root.
#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include "sha256_util.hpp"

namespace vault {

struct MerkleProofStep {
    std::string siblingHash;
    bool siblingIsRight; // true if sibling is to the right of the current node
};

class MerkleTree {
public:
    explicit MerkleTree(std::vector<std::string> leafHashes)
        : leaves_(std::move(leafHashes)) {
        build();
    }

    const std::string& getRoot() const {
        if (levels_.empty() || levels_.back().empty()) {
            static const std::string kEmptyRoot =
                Sha256::hashString("EMPTY_MERKLE_TREE");
            return kEmptyRoot;
        }
        return levels_.back().front();
    }

    std::size_t leafCount() const { return leaves_.size(); }

    // Returns the proof path for leaf at `index`, bottom-up.
    std::vector<MerkleProofStep> getProof(std::size_t index) const {
        if (index >= leaves_.size()) {
            throw std::out_of_range("Merkle leaf index out of range");
        }
        std::vector<MerkleProofStep> proof;
        std::size_t idx = index;
        for (std::size_t level = 0; level + 1 < levels_.size(); ++level) {
            const auto& currentLevel = levels_[level];
            bool isRightNode = (idx % 2 == 1);
            std::size_t siblingIdx = isRightNode ? idx - 1 : idx + 1;
            if (siblingIdx >= currentLevel.size()) {
                siblingIdx = idx; // duplicated-last-node case
            }
            proof.push_back({currentLevel[siblingIdx], !isRightNode});
            idx /= 2;
        }
        return proof;
    }

    // Recompute the root from a leaf hash + proof and compare to expected root.
    static bool verifyProof(const std::string& leafHash,
                             const std::vector<MerkleProofStep>& proof,
                             const std::string& expectedRoot) {
        std::string current = leafHash;
        for (const auto& step : proof) {
            current = step.siblingIsRight
                           ? Sha256::hashPair(current, step.siblingHash)
                           : Sha256::hashPair(step.siblingHash, current);
        }
        return current == expectedRoot;
    }

private:
    std::vector<std::string> leaves_;
    std::vector<std::vector<std::string>> levels_;

    void build() {
        levels_.clear();
        if (leaves_.empty()) {
            return;
        }
        std::vector<std::string> current = leaves_;
        levels_.push_back(current);

        while (current.size() > 1) {
            std::vector<std::string> next;
            next.reserve((current.size() + 1) / 2);
            for (std::size_t i = 0; i < current.size(); i += 2) {
                if (i + 1 < current.size()) {
                    next.push_back(Sha256::hashPair(current[i], current[i + 1]));
                } else {
                    // Odd one out: duplicate it.
                    next.push_back(Sha256::hashPair(current[i], current[i]));
                }
            }
            levels_.push_back(next);
            current = next;
        }
    }
};

} // namespace vault
