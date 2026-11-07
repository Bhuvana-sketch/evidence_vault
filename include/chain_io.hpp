// chain_io.hpp
// Save/load the entire blockchain to a human-readable JSON file. This is
// the primary persistence format; sqlite_store.hpp provides an additional
// queryable backend built on the same Block::toJson()/fromJson().
#pragma once

#include <fstream>
#include <stdexcept>
#include <string>

#include "blockchain.hpp"
#include "nlohmann/json.hpp"

namespace vault {

class ChainIO {
public:
    static void saveToFile(const Blockchain& chain, const std::string& path) {
        json root;
        root["difficulty"] = chain.difficulty();
        json blocksJson = json::array();
        for (const auto& b : chain.blocks()) blocksJson.push_back(b.toJson());
        root["blocks"] = blocksJson;

        std::ofstream out(path);
        if (!out.good()) throw std::runtime_error("Cannot write chain file: " + path);
        out << root.dump(2);
    }

    // Loads a chain from file into a fresh Blockchain object (replacing the
    // auto-generated genesis block with the one stored on disk).
    static Blockchain loadFromFile(const std::string& path) {
        std::ifstream in(path);
        if (!in.good()) throw std::runtime_error("Cannot read chain file: " + path);
        json root;
        in >> root;

        uint32_t difficulty = root.value("difficulty", 4);
        Blockchain chain(difficulty);

        std::vector<Block> blocks;
        for (const auto& bj : root.at("blocks")) blocks.push_back(Block::fromJson(bj));
        chain.replaceChain(std::move(blocks));
        return chain;
    }

    static bool fileExists(const std::string& path) {
        std::ifstream in(path);
        return in.good();
    }
};

} // namespace vault
