// evidence.hpp
// Represents a single piece of digital evidence (log file, config, API
// record dump, etc.) along with its full chain-of-custody history.
#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"

namespace vault {

using json = nlohmann::json;

// Helper: current UTC timestamp as an ISO-8601-ish string.
inline std::string nowTimestamp() {
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tmUtc{};
    gmtime_r(&t, &tmUtc);
    std::ostringstream oss;
    oss << std::put_time(&tmUtc, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

enum class CustodyAction { CREATED, REVIEWED, TRANSFERRED, ARCHIVED, VERIFIED, TAMPER_DETECTED };

inline std::string custodyActionToString(CustodyAction a) {
    switch (a) {
        case CustodyAction::CREATED:          return "CREATED";
        case CustodyAction::REVIEWED:         return "REVIEWED";
        case CustodyAction::TRANSFERRED:      return "TRANSFERRED";
        case CustodyAction::ARCHIVED:         return "ARCHIVED";
        case CustodyAction::VERIFIED:         return "VERIFIED";
        case CustodyAction::TAMPER_DETECTED:  return "TAMPER_DETECTED";
    }
    return "UNKNOWN";
}

inline CustodyAction custodyActionFromString(const std::string& s) {
    if (s == "CREATED") return CustodyAction::CREATED;
    if (s == "REVIEWED") return CustodyAction::REVIEWED;
    if (s == "TRANSFERRED") return CustodyAction::TRANSFERRED;
    if (s == "ARCHIVED") return CustodyAction::ARCHIVED;
    if (s == "VERIFIED") return CustodyAction::VERIFIED;
    if (s == "TAMPER_DETECTED") return CustodyAction::TAMPER_DETECTED;
    return CustodyAction::CREATED;
}

struct CustodyEntry {
    CustodyAction action;
    std::string actor;       // who performed the action
    std::string timestamp;   // ISO-8601 UTC
    std::string notes;       // free-text detail

    json toJson() const {
        return json{{"action", custodyActionToString(action)},
                     {"actor", actor},
                     {"timestamp", timestamp},
                     {"notes", notes}};
    }

    static CustodyEntry fromJson(const json& j) {
        CustodyEntry e;
        e.action = custodyActionFromString(j.at("action").get<std::string>());
        e.actor = j.at("actor").get<std::string>();
        e.timestamp = j.at("timestamp").get<std::string>();
        e.notes = j.value("notes", "");
        return e;
    }
};

struct EvidenceRecord {
    std::string evidenceId;     // unique id, e.g. "EVD-0001"
    std::string originalPath;   // path on disk at ingestion time
    std::string fileName;       // display name
    std::string fileHash;       // SHA-256 of file contents at ingestion
    std::size_t fileSizeBytes = 0;
    std::string ingestedAt;     // ISO-8601 UTC
    std::string description;
    std::vector<CustodyEntry> custodyLog;

    void addCustodyEntry(CustodyAction action, const std::string& actor,
                          const std::string& notes = "") {
        custodyLog.push_back(CustodyEntry{action, actor, nowTimestamp(), notes});
    }

    json toJson() const {
        json custody = json::array();
        for (const auto& c : custodyLog) custody.push_back(c.toJson());
        return json{{"evidenceId", evidenceId},
                     {"originalPath", originalPath},
                     {"fileName", fileName},
                     {"fileHash", fileHash},
                     {"fileSizeBytes", fileSizeBytes},
                     {"ingestedAt", ingestedAt},
                     {"description", description},
                     {"custodyLog", custody}};
    }

    static EvidenceRecord fromJson(const json& j) {
        EvidenceRecord e;
        e.evidenceId = j.at("evidenceId").get<std::string>();
        e.originalPath = j.at("originalPath").get<std::string>();
        e.fileName = j.at("fileName").get<std::string>();
        e.fileHash = j.at("fileHash").get<std::string>();
        e.fileSizeBytes = j.at("fileSizeBytes").get<std::size_t>();
        e.ingestedAt = j.at("ingestedAt").get<std::string>();
        e.description = j.value("description", "");
        for (const auto& c : j.at("custodyLog")) {
            e.custodyLog.push_back(CustodyEntry::fromJson(c));
        }
        return e;
    }
};

} // namespace vault
