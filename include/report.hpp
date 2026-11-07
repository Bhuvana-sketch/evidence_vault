// report.hpp
// Formats a ValidationReport into a readable integrity report, both for
// printing to the console and for saving as a timestamped text file under
// reports/. This is the "automated integrity report showing exactly which
// records were compromised" deliverable.
#pragma once

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "blockchain.hpp"
#include "evidence.hpp"

namespace vault {

class ReportGenerator {
public:
    static std::string format(const ValidationReport& report, const Blockchain& chain) {
        std::ostringstream oss;
        oss << "========================================================\n";
        oss << " DIGITAL EVIDENCE INTEGRITY VAULT -- INTEGRITY REPORT\n";
        oss << " Generated: " << nowTimestamp() << "\n";
        oss << " Chain length: " << chain.blocks().size() << " blocks (incl. genesis)\n";
        oss << " Mining difficulty: " << chain.difficulty() << " leading zero hex chars\n";
        oss << "========================================================\n\n";

        oss << "[1] CHAIN STRUCTURAL VALIDATION\n";
        oss << "--------------------------------------------------------\n";
        if (report.brokenLinks.empty()) {
            oss << "  OK  All block links, hashes, and proof-of-work checks passed.\n";
        } else {
            oss << "  FAIL  Chain integrity COMPROMISED.\n";
            oss << "  First affected block: #" << report.firstAffectedBlock << "\n";
            oss << "  (Every block from this point forward is untrustworthy,\n";
            oss << "   since the hash chain linkage is broken here.)\n\n";
            for (const auto& issue : report.brokenLinks) {
                oss << "  Block #" << issue.blockIndex << ": " << issue.description << "\n";
            }
        }
        oss << "\n";

        oss << "[2] EVIDENCE FILE TAMPER CHECK\n";
        oss << "--------------------------------------------------------\n";
        std::size_t tamperedCount = 0, missingCount = 0;
        for (const auto& f : report.tamperFindings) {
            if (f.fileMissing) ++missingCount;
            else if (f.tampered) ++tamperedCount;
        }
        oss << "  Records checked: " << report.tamperFindings.size()
            << " | Tampered: " << tamperedCount
            << " | Missing: " << missingCount << "\n\n";

        for (const auto& f : report.tamperFindings) {
            if (f.fileMissing) {
                oss << "  [MISSING]   " << f.evidenceId << " (" << f.fileName
                    << ") in block #" << f.blockIndex
                    << " -- file no longer found at recorded path.\n";
            } else if (f.tampered) {
                oss << "  [TAMPERED]  " << f.evidenceId << " (" << f.fileName
                    << ") in block #" << f.blockIndex << "\n";
                oss << "              stored  hash: " << f.storedHash << "\n";
                oss << "              current hash: " << f.currentHash << "\n";
            } else {
                oss << "  [OK]        " << f.evidenceId << " (" << f.fileName
                    << ") in block #" << f.blockIndex << " -- hash matches ledger.\n";
            }
        }

        oss << "\n[3] OVERALL VERDICT\n";
        oss << "--------------------------------------------------------\n";
        if (!report.anyIssues()) {
            oss << "  VAULT INTEGRITY: VERIFIED. No tampering detected.\n";
        } else {
            oss << "  VAULT INTEGRITY: COMPROMISED. Tampering detected -- see above.\n";
        }
        oss << "========================================================\n";
        return oss.str();
    }

    static void printToConsole(const ValidationReport& report, const Blockchain& chain) {
        std::cout << format(report, chain) << std::endl;
    }

    static std::string saveToFile(const ValidationReport& report, const Blockchain& chain,
                                   const std::string& dir = "reports") {
        auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm tmUtc{};
        gmtime_r(&t, &tmUtc);
        std::ostringstream fname;
        fname << dir << "/integrity_report_" << std::put_time(&tmUtc, "%Y%m%dT%H%M%SZ") << ".txt";
        std::ofstream out(fname.str());
        out << format(report, chain);
        return fname.str();
    }
};

} // namespace vault
