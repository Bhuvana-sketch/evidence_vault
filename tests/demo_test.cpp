// demo_test.cpp
// Non-interactive walkthrough of the whole system: ingest evidence, log
// custody events, validate a clean chain, simulate two kinds of tampering,
// and show the integrity report catching both. Useful both as a smoke test
// and as a scripted demo of the "unique feature" (tamper simulation +
// automated integrity report).
#include <cassert>
#include <fstream>
#include <iostream>

#include "blockchain.hpp"
#include "chain_io.hpp"
#include "report.hpp"
#include "sqlite_store.hpp"

using namespace vault;

static void writeSampleFile(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary);
    out << content;
}

static void section(const std::string& title) {
    std::cout << "\n################ " << title << " ################\n";
}

int main() {
    section("SETUP: create sample evidence files");
    writeSampleFile("evidence_files/access.log",
                     "2026-11-01 09:14:02 user=alice action=LOGIN result=SUCCESS\n"
                     "2026-11-01 09:15:40 user=alice action=READ file=report.pdf\n");
    writeSampleFile("evidence_files/firewall_config.json",
                     "{\"rules\": [{\"port\": 443, \"action\": \"allow\"}, {\"port\": 23, \"action\": \"deny\"}]}\n");
    writeSampleFile("evidence_files/api_records.csv",
                     "timestamp,endpoint,status\n2026-11-01T09:00:00Z,/v1/login,200\n2026-11-01T09:01:12Z,/v1/export,200\n");

    Blockchain chain(4); // difficulty 4 for a fast demo

    section("STEP 1: Ingest evidence (hash + mine blocks)");
    std::string id1 = chain.addEvidence("evidence_files/access.log", "officer.jane", "Server access log, Nov 1 shift");
    std::string id2 = chain.addEvidence("evidence_files/firewall_config.json", "officer.jane", "Firewall config snapshot");
    std::string id3 = chain.addEvidence("evidence_files/api_records.csv", "officer.mark", "API gateway export");
    std::cout << "Ingested: " << id1 << ", " << id2 << ", " << id3 << "\n";
    std::cout << "Chain now has " << chain.blocks().size() << " blocks (incl. genesis)\n";

    section("STEP 2: Chain-of-custody events");
    chain.addCustodyEvent(id1, CustodyAction::REVIEWED, "analyst.sam", "Initial review for anomalies");
    chain.addCustodyEvent(id2, CustodyAction::TRANSFERRED, "officer.jane", "Transferred to forensics team");
    chain.addCustodyEvent(id3, CustodyAction::ARCHIVED, "analyst.sam", "Archived after case closure review");
    auto rec1 = chain.findEvidence(id1);
    assert(rec1 && rec1->custodyLog.size() == 2);
    std::cout << "Custody log for " << id1 << ":\n";
    for (auto& c : rec1->custodyLog) {
        std::cout << "  [" << c.timestamp << "] " << custodyActionToString(c.action)
                  << " by " << c.actor << " -- " << c.notes << "\n";
    }

    section("STEP 3: Validate clean chain (should PASS)");
    {
        auto report = chain.generateIntegrityReport();
        ReportGenerator::printToConsole(report, chain);
        assert(!report.anyIssues() && "Clean chain unexpectedly reported issues");
        std::cout << ">>> ASSERTION PASSED: clean chain validates with no issues.\n";
    }

    section("STEP 4: Merkle proof verification for a single record");
    for (const auto& block : chain.blocks()) {
        for (std::size_t i = 0; i < block.records.size(); ++i) {
            if (block.records[i].evidenceId == id2) {
                std::vector<std::string> leafHashes;
                for (auto& r : block.records) leafHashes.push_back(r.fileHash);
                MerkleTree tree(leafHashes);
                auto proof = tree.getProof(i);
                bool ok = MerkleTree::verifyProof(block.records[i].fileHash, proof, block.merkleRoot);
                std::cout << id2 << " Merkle proof verification: " << (ok ? "PASS" : "FAIL") << "\n";
                assert(ok);
            }
        }
    }

    section("STEP 5: TAMPER SIMULATION #1 -- modify evidence file on disk");
    bool t1 = chain.simulateFileTamper(id1, "unauthorized log line: user=mallory action=DELETE_LOGS");
    assert(t1);
    std::cout << "File " << id1 << " modified on disk WITHOUT updating the ledger.\n";

    section("STEP 6: TAMPER SIMULATION #2 -- corrupt ledger hash directly (no re-mine)");
    bool t2 = chain.simulateLedgerTamper(id3, std::string(64, 'f'));
    assert(t2);
    std::cout << "Ledger entry for " << id3 << " corrupted directly (hash overwritten).\n";

    section("STEP 7: Validate chain AFTER tampering (should FAIL + pinpoint records)");
    {
        auto report = chain.generateIntegrityReport();
        ReportGenerator::printToConsole(report, chain);
        assert(report.anyIssues() && "Tampering was not detected!");

        bool foundFileTamper = false;
        for (auto& f : report.tamperFindings) {
            if (f.evidenceId == id1 && f.tampered) foundFileTamper = true;
        }
        assert(foundFileTamper && "File-level tamper on id1 was not flagged");
        // id3's tampering was a direct ledger edit (not a file edit), so it's
        // caught by the chain structural validation (brokenLinks), checked below.
        assert(!report.brokenLinks.empty() && "Ledger corruption did not break chain validation");
        std::cout << ">>> ASSERTION PASSED: both tamper modes were detected.\n";
        std::cout << ">>> File tamper flagged on " << id1 << ": " << foundFileTamper << "\n";
        std::cout << ">>> Ledger corruption broke chain at block #" << report.firstAffectedBlock << "\n";

        std::string savedPath = ReportGenerator::saveToFile(report, chain);
        std::cout << "Integrity report saved to: " << savedPath << "\n";
    }

    section("STEP 8: Persistence round-trip (JSON + SQLite)");
    ChainIO::saveToFile(chain, "data/chain.json");
    {
        SqliteStore store("data/vault.db");
        for (auto& b : chain.blocks()) store.saveBlock(b);
    }
    Blockchain reloaded = ChainIO::loadFromFile("data/chain.json");
    assert(reloaded.blocks().size() == chain.blocks().size());
    std::cout << "Reloaded chain from JSON: " << reloaded.blocks().size() << " blocks match original.\n";
    {
        SqliteStore store("data/vault.db");
        auto dbBlocks = store.loadAllBlocks();
        assert(dbBlocks.size() == chain.blocks().size());
        std::cout << "Reloaded chain from SQLite: " << dbBlocks.size() << " blocks match original.\n";
    }

    // Reloaded chain should still show the same tampering (it's data, not state).
    {
        auto report2 = reloaded.generateIntegrityReport();
        assert(report2.anyIssues());
        std::cout << "Reloaded chain still correctly reports tampering: YES\n";
    }

    section("ALL DEMO STEPS COMPLETED SUCCESSFULLY");
    std::cout << "\nSummary: evidence ingestion, chain-of-custody, Merkle proofs,\n"
                 "chain validation, dual tamper-simulation modes, integrity\n"
                 "reporting, and JSON+SQLite persistence all verified working.\n";
    return 0;
}
