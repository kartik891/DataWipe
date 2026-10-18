#pragma once
// Ed25519 signing keys for TECC certificates, via OpenSSL libcrypto (EVP interface).
//
// Why Ed25519: deterministic signatures (no per-signature randomness to get wrong), 32-byte
// public keys that fit on a printed certificate, fast verification, and support in every
// current OpenSSL. Why OpenSSL and not hand-written code: signature code in a public security
// product must be a vetted implementation; FIPS-validated OpenSSL builds exist.
//
// Key custody (paper Section VI): each organisation generates its own key pair with
// `datawipe keygen` and publishes the public key through a channel auditors already trust.
// The private key file is PKCS#8 PEM, encrypted with AES-256-CBC under a passphrase unless the
// operator explicitly opts out; the file is created 0600 and never overwritten.

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "core/result.hpp"

typedef struct evp_pkey_st EVP_PKEY;

namespace dw::ed25519 {

using PublicKey = std::array<std::uint8_t, 32>;
using Signature = std::array<std::uint8_t, 64>;

// Short identifier for a public key: first 16 hex digits of SHA-256(raw public key).
std::string key_id(const PublicKey& pub);

class PrivateKey {
public:
    static Result<PrivateKey> generate();
    // `passphrase` empty: the file is written unencrypted (only on explicit request).
    Result<void> save(const std::string& path, const std::string& passphrase) const;
    // Asks `passphrase()` only if the file is encrypted.
    static Result<PrivateKey> load(const std::string& path, const std::function<std::string()>& passphrase);

    PublicKey public_key() const;
    Result<Signature> sign(std::span<const std::uint8_t> message) const;

private:
    struct Free {
        void operator()(EVP_PKEY* k) const;
    };
    explicit PrivateKey(EVP_PKEY* k) : key_(k) {}
    std::unique_ptr<EVP_PKEY, Free> key_;
};

Result<void> save_public_key(const PublicKey& pub, const std::string& path);
Result<PublicKey> load_public_key(const std::string& path);

bool verify(const PublicKey& pub, std::span<const std::uint8_t> message, const Signature& sig);

}  // namespace dw::ed25519
