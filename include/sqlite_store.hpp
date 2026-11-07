// sqlite_store.hpp
// Minimal SQLite persistence layer for the blockchain. Stores one row per
// block (with its full JSON payload) plus a flat evidence index table for
// fast lookup by evidenceId. JSON-file persistence (chain_io.hpp) remains
// the primary human-readable export; SQLite backs it with a queryable store.
#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "block.hpp"

namespace vault {

class SqliteStore {
public:
    explicit SqliteStore(const std::string& dbPath) {
        if (sqlite3_open(dbPath.c_str(), &db_) != SQLITE_OK) {
            std::string err = db_ ? sqlite3_errmsg(db_) : "unknown error";
            throw std::runtime_error("Failed to open SQLite DB: " + err);
        }
        exec("PRAGMA foreign_keys = ON;");
        exec(R"sql(
            CREATE TABLE IF NOT EXISTS blocks (
                block_index INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                difficulty INTEGER NOT NULL,
                hash TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
        )sql");
        exec(R"sql(
            CREATE TABLE IF NOT EXISTS evidence_index (
                evidence_id TEXT PRIMARY KEY,
                block_index INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                FOREIGN KEY(block_index) REFERENCES blocks(block_index)
            );
        )sql");
    }

    ~SqliteStore() {
        if (db_) sqlite3_close(db_);
    }

    SqliteStore(const SqliteStore&) = delete;
    SqliteStore& operator=(const SqliteStore&) = delete;

    void saveBlock(const Block& b) {
        exec("BEGIN TRANSACTION;");
        try {
            const char* sql =
                "INSERT INTO blocks (block_index, timestamp, previous_hash, merkle_root, "
                "nonce, difficulty, hash, payload_json) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(block_index) DO UPDATE SET "
                "timestamp=excluded.timestamp, previous_hash=excluded.previous_hash, "
                "merkle_root=excluded.merkle_root, nonce=excluded.nonce, "
                "difficulty=excluded.difficulty, hash=excluded.hash, "
                "payload_json=excluded.payload_json;";
            sqlite3_stmt* stmt = prepare(sql);
            std::string payload = b.toJson().dump();
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(b.index));
            sqlite3_bind_text(stmt, 2, b.timestamp.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, b.previousHash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, b.merkleRoot.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(b.nonce));
            sqlite3_bind_int(stmt, 6, static_cast<int>(b.difficulty));
            sqlite3_bind_text(stmt, 7, b.hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 8, payload.c_str(), -1, SQLITE_TRANSIENT);
            step(stmt);
            sqlite3_finalize(stmt);

            // Refresh evidence_index entries for this block's records.
            const char* delSql = "DELETE FROM evidence_index WHERE block_index = ?;";
            sqlite3_stmt* delStmt = prepare(delSql);
            sqlite3_bind_int64(delStmt, 1, static_cast<sqlite3_int64>(b.index));
            step(delStmt);
            sqlite3_finalize(delStmt);

            const char* insSql =
                "INSERT INTO evidence_index (evidence_id, block_index, file_name, "
                "file_hash, ingested_at) VALUES (?,?,?,?,?);";
            for (const auto& rec : b.records) {
                sqlite3_stmt* insStmt = prepare(insSql);
                sqlite3_bind_text(insStmt, 1, rec.evidenceId.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(insStmt, 2, static_cast<sqlite3_int64>(b.index));
                sqlite3_bind_text(insStmt, 3, rec.fileName.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(insStmt, 4, rec.fileHash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(insStmt, 5, rec.ingestedAt.c_str(), -1, SQLITE_TRANSIENT);
                step(insStmt);
                sqlite3_finalize(insStmt);
            }
            exec("COMMIT;");
        } catch (...) {
            exec("ROLLBACK;");
            throw;
        }
    }

    std::vector<Block> loadAllBlocks() {
        std::vector<Block> blocks;
        const char* sql = "SELECT payload_json FROM blocks ORDER BY block_index ASC;";
        sqlite3_stmt* stmt = prepare(sql);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmt, 0);
            std::string payload(reinterpret_cast<const char*>(text));
            blocks.push_back(Block::fromJson(json::parse(payload)));
        }
        sqlite3_finalize(stmt);
        return blocks;
    }

private:
    sqlite3* db_ = nullptr;

    void exec(const std::string& sql) {
        char* errMsg = nullptr;
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
            std::string err = errMsg ? errMsg : "unknown error";
            sqlite3_free(errMsg);
            throw std::runtime_error("SQLite exec failed: " + err);
        }
    }

    sqlite3_stmt* prepare(const std::string& sql) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("SQLite prepare failed: ") + sqlite3_errmsg(db_));
        }
        return stmt;
    }

    void step(sqlite3_stmt* stmt) {
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            throw std::runtime_error(std::string("SQLite step failed: ") + sqlite3_errmsg(db_));
        }
    }
};

} // namespace vault
