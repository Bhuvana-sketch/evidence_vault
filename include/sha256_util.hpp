// sha256_util.hpp
// Thin wrapper around OpenSSL's EVP digest API for SHA-256 hashing.
// Supports hashing raw strings/bytes as well as streaming a file from disk
// in fixed-size chunks so large evidence files don't need to be loaded
// entirely into memory.
#pragma once

#include <array>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace vault {

class Sha256 {
public:
    // Hash an in-memory buffer (e.g. a string) and return the lowercase hex digest.
    static std::string hashString(const std::string& data) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to allocate EVP_MD_CTX");

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
            EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA-256 digest computation failed");
        }
        EVP_MD_CTX_free(ctx);
        return toHex(digest, digestLen);
    }

    // Hash the contents of a file on disk, streaming in chunks.
    // Throws std::runtime_error if the file cannot be opened.
    static std::string hashFile(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file for hashing: " + path);
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to allocate EVP_MD_CTX");
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA-256 init failed");
        }

        constexpr std::size_t kChunkSize = 1 << 16; // 64 KB
        std::vector<char> buffer(kChunkSize);

        while (file.good()) {
            file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            std::streamsize got = file.gcount();
            if (got > 0) {
                if (EVP_DigestUpdate(ctx, buffer.data(), static_cast<size_t>(got)) != 1) {
                    EVP_MD_CTX_free(ctx);
                    throw std::runtime_error("SHA-256 update failed while reading " + path);
                }
            }
        }

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA-256 finalize failed for " + path);
        }
        EVP_MD_CTX_free(ctx);
        return toHex(digest, digestLen);
    }

    // Convenience: combine two hex-digest strings and hash the concatenation.
    // Used heavily by the Merkle tree and block-hash computation.
    static std::string hashPair(const std::string& a, const std::string& b) {
        return hashString(a + b);
    }

private:
    static std::string toHex(const unsigned char* bytes, unsigned int len) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < len; ++i) {
            oss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return oss.str();
    }
};

} // namespace vault
