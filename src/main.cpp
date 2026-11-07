// main.cpp
// Digital Evidence Integrity Vault -- CLI driver.
// Menu-driven console app wiring together the blockchain, evidence ingest,
// chain-of-custody, tamper simulation, validation, and reporting modules.
#include <iostream>
#include <limits>
#include <sstream>
#include <string>

#include "blockchain.hpp"
#include "chain_io.hpp"
#include "evidence.hpp"
#include "report.hpp"
#include "sqlite_store.hpp"

namespace {

constexpr const char* kChainFile = "data/chain.json";
constexpr const char* kDbFile = "data/vault.db";

void printHeader() {
    std::cout << "\n==========================================================\n";
    std::cout << "   DIGITAL EVIDENCE INTEGRITY VAULT -- Blockchain (C++17)\n";
    std::cout << "==========================================================\n";
}

void printMenu() {
    std::cout << "\n--- MAIN MENU -------------------------------------------\n"
              << " 1. Add evidence file (hash + mine new block)\n"
              << " 2. List all evidence records\n"
              << " 3. Show chain-of-custody for an evidence record\n"
              << " 4. Add custody event (review/transfer/archive)\n"
              << " 5. Validate chain + run integrity report\n"
              << " 6. View full blockchain (block details)\n"
              << " 7. TAMPER SIMULATION: modify evidence file on disk\n"
              << " 8. TAMPER SIMULATION: corrupt ledger record directly\n"
              << " 9. Verify a single evidence record via Merkle proof\n"
              << "10. Save chain (JSON + SQLite)\n"
              << "11. Load chain from JSON\n"
              << " 0. Exit\n"
              << "----------------------------------------------------------\n"
              << "Choice: ";
}

std::string readLine(const std::string& prompt) {
    std::cout << prompt;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

int readInt(const std::string& prompt) {
    std::cout << prompt;
    int value;
    while (!(std::cin >> value)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Please enter a number: ";
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return value;
}

void addEvidence(vault::Blockchain& chain) {
    std::string path = readLine("Path to evidence file: ");
    std::string actor = readLine("Actor (your name/ID): ");
    std::string desc = readLine("Description (optional): ");
    try {
        std::string id = chain.addEvidence(path, actor, desc);
        std::cout << "Evidence ingested as " << id << " and mined into block #"
                  << (chain.blocks().size() - 1) << ".\n";
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
    }
}

void listEvidence(const vault::Blockchain& chain) {
    std::cout << "\nEvidence Ledger\n" << std::string(58, '-') << "\n";
    bool any = false;
    for (const auto& block : chain.blocks()) {
        for (const auto& rec : block.records) {
            any = true;
            std::cout << rec.evidenceId << "  | block #" << block.index
                      << " | " << rec.fileName << " | " << rec.fileSizeBytes
                      << " bytes | ingested " << rec.ingestedAt << "\n";
            std::cout << "    hash: " << rec.fileHash << "\n";
        }
    }
    if (!any) std::cout << "(no evidence ingested yet)\n";
}

void showCustody(const vault::Blockchain& chain) {
    std::string id = readLine("Evidence ID (e.g. EVD-0001): ");
    auto rec = chain.findEvidence(id);
    if (!rec) {
        std::cout << "No such evidence record.\n";
        return;
    }
    std::cout << "\nChain of Custody for " << rec->evidenceId << " (" << rec->fileName << ")\n";
    std::cout << std::string(58, '-') << "\n";
    for (const auto& c : rec->custodyLog) {
        std::cout << "[" << c.timestamp << "] " << vault::custodyActionToString(c.action)
                  << " by " << c.actor;
        if (!c.notes.empty()) std::cout << " -- " << c.notes;
        std::cout << "\n";
    }
}

void addCustodyEvent(vault::Blockchain& chain) {
    std::string id = readLine("Evidence ID: ");
    std::cout << "Action: 1=REVIEWED 2=TRANSFERRED 3=ARCHIVED 4=VERIFIED: ";
    int choice; std::cin >> choice; std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    vault::CustodyAction action = vault::CustodyAction::REVIEWED;
    switch (choice) {
        case 1: action = vault::CustodyAction::REVIEWED; break;
        case 2: action = vault::CustodyAction::TRANSFERRED; break;
        case 3: action = vault::CustodyAction::ARCHIVED; break;
        case 4: action = vault::CustodyAction::VERIFIED; break;
        default: std::cout << "Invalid choice, defaulting to REVIEWED.\n";
    }
    std::string actor = readLine("Actor: ");
    std::string notes = readLine("Notes: ");
    if (chain.addCustodyEvent(id, action, actor, notes)) {
        std::cout << "Custody event recorded and affected block(s) re-mined.\n";
    } else {
        std::cout << "No such evidence record.\n";
    }
}

void validateAndReport(const vault::Blockchain& chain) {
    auto report = chain.generateIntegrityReport();
    vault::ReportGenerator::printToConsole(report, chain);
    std::string path = vault::ReportGenerator::saveToFile(report, chain);
    std::cout << "Report saved to: " << path << "\n";
}

void viewChain(const vault::Blockchain& chain) {
    std::cout << "\nBlockchain (" << chain.blocks().size() << " blocks)\n";
    std::cout << std::string(58, '=') << "\n";
    for (const auto& b : chain.blocks()) {
        std::cout << "Block #" << b.index << "\n";
        std::cout << "  timestamp     : " << b.timestamp << "\n";
        std::cout << "  previousHash  : " << b.previousHash << "\n";
        std::cout << "  merkleRoot    : " << b.merkleRoot << "\n";
        std::cout << "  nonce         : " << b.nonce << "\n";
        std::cout << "  difficulty    : " << b.difficulty << "\n";
        std::cout << "  hash          : " << b.hash << "\n";
        std::cout << "  records       : " << b.records.size() << "\n";
        for (const auto& r : b.records) {
            std::cout << "     - " << r.evidenceId << " (" << r.fileName << ")\n";
        }
        std::cout << std::string(58, '-') << "\n";
    }
}

void tamperFile(vault::Blockchain& chain) {
    std::string id = readLine("Evidence ID to tamper with (file on disk): ");
    std::string injected = readLine("Text to inject into the file: ");
    if (chain.simulateFileTamper(id, injected)) {
        std::cout << "Simulated tampering complete. The file on disk has been modified\n"
                     "WITHOUT updating the ledger. Run option 5 to see it get caught.\n";
    } else {
        std::cout << "Could not tamper (evidence not found or file not writable).\n";
    }
}

void tamperLedger(vault::Blockchain& chain) {
    std::string id = readLine("Evidence ID to corrupt in the ledger: ");
    std::string fakeHash = readLine("Fake hash to inject (any string, e.g. 'deadbeef...'): ");
    if (chain.simulateLedgerTamper(id, fakeHash)) {
        std::cout << "Simulated ledger corruption complete. The stored fileHash was\n"
                     "overwritten directly, WITHOUT re-mining the block. Run option 5\n"
                     "to see the broken chain link and merkle mismatch get caught.\n";
    } else {
        std::cout << "Could not tamper (evidence not found).\n";
    }
}

void verifyMerkleProof(const vault::Blockchain& chain) {
    std::string id = readLine("Evidence ID to verify via Merkle proof: ");
    for (const auto& block : chain.blocks()) {
        for (std::size_t i = 0; i < block.records.size(); ++i) {
            if (block.records[i].evidenceId == id) {
                std::vector<std::string> leafHashes;
                for (const auto& r : block.records) leafHashes.push_back(r.fileHash);
                vault::MerkleTree tree(leafHashes);
                auto proof = tree.getProof(i);
                bool ok = vault::MerkleTree::verifyProof(block.records[i].fileHash, proof, block.merkleRoot);
                std::cout << "Merkle root (block #" << block.index << "): " << block.merkleRoot << "\n";
                std::cout << "Proof steps: " << proof.size() << "\n";
                std::cout << "Verification: " << (ok ? "PASS -- record is part of this block's committed set."
                                                       : "FAIL -- record does NOT match the committed merkle root.") << "\n";
                return;
            }
        }
    }
    std::cout << "No such evidence record.\n";
}

void saveChain(const vault::Blockchain& chain) {
    try {
        vault::ChainIO::saveToFile(chain, kChainFile);
        std::cout << "Chain saved to " << kChainFile << "\n";

        vault::SqliteStore store(kDbFile);
        for (const auto& b : chain.blocks()) store.saveBlock(b);
        std::cout << "Chain persisted to SQLite DB at " << kDbFile << "\n";
    } catch (const std::exception& e) {
        std::cout << "Save failed: " << e.what() << "\n";
    }
}

bool loadChain(vault::Blockchain& chain) {
    try {
        if (!vault::ChainIO::fileExists(kChainFile)) {
            std::cout << "No existing chain file found at " << kChainFile << ". Starting fresh.\n";
            return false;
        }
        chain = vault::ChainIO::loadFromFile(kChainFile);
        std::cout << "Chain loaded from " << kChainFile << " (" << chain.blocks().size() << " blocks).\n";
        return true;
    } catch (const std::exception& e) {
        std::cout << "Load failed: " << e.what() << ". Starting fresh.\n";
        return false;
    }
}

} // namespace

int main() {
    printHeader();
    vault::Blockchain chain(4); // difficulty: 4 leading hex zeros
    loadChain(chain);

    bool running = true;
    while (running) {
        printMenu();
        int choice = readInt("");
        switch (choice) {
            case 1: addEvidence(chain); break;
            case 2: listEvidence(chain); break;
            case 3: showCustody(chain); break;
            case 4: addCustodyEvent(chain); break;
            case 5: validateAndReport(chain); break;
            case 6: viewChain(chain); break;
            case 7: tamperFile(chain); break;
            case 8: tamperLedger(chain); break;
            case 9: verifyMerkleProof(chain); break;
            case 10: saveChain(chain); break;
            case 11: loadChain(chain); break;
            case 0: running = false; break;
            default: std::cout << "Invalid choice.\n";
        }
    }

    std::cout << "\nSaving chain before exit...\n";
    saveChain(chain);
    std::cout << "Goodbye.\n";
    return 0;
}
