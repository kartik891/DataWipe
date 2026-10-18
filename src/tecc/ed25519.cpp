#include "tecc/ed25519.hpp"

#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <functional>

#include "core/sha256.hpp"

namespace dw::ed25519 {

namespace {

std::string openssl_error(const std::string& what) {
    std::string msg = what;
    if (unsigned long e = ERR_get_error()) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof buf);
        msg += ": ";
        msg += buf;
    }
    ERR_clear_error();
    return msg;
}

struct BioFree {
    void operator()(BIO* b) const { BIO_free(b); }
};
struct CtxFree {
    void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};

// Creates `path` exclusively with `mode` and writes `data`: key files are never overwritten.
Result<void> write_new_file(const std::string& path, std::string_view data, mode_t mode) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) return sys_error("create " + path);
    for (std::size_t done = 0; done < data.size();) {
        ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            const int err = errno;
            ::close(fd);
            ::unlink(path.c_str());
            return sys_error("write " + path, err);
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    if (!synced) return sys_error("fsync " + path);
    return ok();
}

std::string bio_string(BIO* b) {
    char* p = nullptr;
    const long n = BIO_get_mem_data(b, &p);
    return std::string(p, static_cast<std::size_t>(n));
}

Result<std::string> read_file(const std::string& path) {
    std::unique_ptr<FILE, int (*)(FILE*)> f(std::fopen(path.c_str(), "rb"), &std::fclose);
    if (!f) return sys_error("open " + path);
    std::string s;
    char buf[4096];
    while (std::size_t n = std::fread(buf, 1, sizeof buf, f.get())) s.append(buf, n);
    return s;
}

}  // namespace

void PrivateKey::Free::operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); }

std::string key_id(const PublicKey& pub) {
    Sha256 h;
    h.update(std::as_bytes(std::span(pub)));
    return to_hex(std::span<const std::uint8_t>(h.finish())).substr(0, 16);
}

Result<PrivateKey> PrivateKey::generate() {
    EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    if (!k) return error(openssl_error("Ed25519 key generation failed"));
    return PrivateKey(k);
}

Result<void> PrivateKey::save(const std::string& path, const std::string& passphrase) const {
    std::unique_ptr<BIO, BioFree> bio(BIO_new(BIO_s_mem()));
    if (!bio) return error(openssl_error("BIO_new"));
    const EVP_CIPHER* cipher = passphrase.empty() ? nullptr : EVP_aes_256_cbc();
    if (PEM_write_bio_PKCS8PrivateKey(bio.get(), key_.get(), cipher, passphrase.empty() ? nullptr : passphrase.data(),
                                      static_cast<int>(passphrase.size()), nullptr, nullptr) != 1)
        return error(openssl_error("cannot encode the private key"));
    return write_new_file(path, bio_string(bio.get()), 0600);
}

Result<PrivateKey> PrivateKey::load(const std::string& path, const std::function<std::string()>& passphrase) {
    auto text = read_file(path);
    if (!text) return text.error();
    std::unique_ptr<BIO, BioFree> bio(BIO_new_mem_buf(text->data(), static_cast<int>(text->size())));
    // OpenSSL calls back only when the PEM block is encrypted.
    struct Ctx {
        const std::function<std::string()>* ask;
        bool asked = false;
    } ctx{&passphrase};
    auto cb = [](char* buf, int size, int, void* u) -> int {
        auto* c = static_cast<Ctx*>(u);
        c->asked = true;
        if (!*c->ask) return -1;
        const std::string p = (*c->ask)();
        if (p.empty() || int(p.size()) > size) return -1;
        std::memcpy(buf, p.data(), p.size());
        return static_cast<int>(p.size());
    };
    EVP_PKEY* k = PEM_read_bio_PrivateKey(bio.get(), nullptr, cb, &ctx);
    if (!k)
        return error(openssl_error(ctx.asked ? "cannot decrypt " + path + " (wrong passphrase?)"
                                              : "cannot read private key " + path));
    if (EVP_PKEY_get_base_id(k) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(k);
        return error(path + " is not an Ed25519 key");
    }
    return PrivateKey(k);
}

PublicKey PrivateKey::public_key() const {
    PublicKey pub{};
    std::size_t len = pub.size();
    EVP_PKEY_get_raw_public_key(key_.get(), pub.data(), &len);
    return pub;
}

Result<Signature> PrivateKey::sign(std::span<const std::uint8_t> message) const {
    std::unique_ptr<EVP_MD_CTX, CtxFree> ctx(EVP_MD_CTX_new());
    Signature sig{};
    std::size_t len = sig.size();
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key_.get()) != 1 ||
        EVP_DigestSign(ctx.get(), sig.data(), &len, message.data(), message.size()) != 1 || len != sig.size())
        return error(openssl_error("Ed25519 signing failed"));
    return sig;
}

Result<void> save_public_key(const PublicKey& pub, const std::string& path) {
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!k) return error(openssl_error("cannot build the public key"));
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> key(k, &EVP_PKEY_free);
    std::unique_ptr<BIO, BioFree> bio(BIO_new(BIO_s_mem()));
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key.get()) != 1) return error(openssl_error("cannot encode the public key"));
    return write_new_file(path, bio_string(bio.get()), 0644);
}

Result<PublicKey> load_public_key(const std::string& path) {
    auto text = read_file(path);
    if (!text) return text.error();
    std::unique_ptr<BIO, BioFree> bio(BIO_new_mem_buf(text->data(), static_cast<int>(text->size())));
    EVP_PKEY* k = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!k) return error(openssl_error("cannot read public key " + path));
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> key(k, &EVP_PKEY_free);
    if (EVP_PKEY_get_base_id(k) != EVP_PKEY_ED25519) return error(path + " is not an Ed25519 public key");
    PublicKey pub{};
    std::size_t len = pub.size();
    if (EVP_PKEY_get_raw_public_key(k, pub.data(), &len) != 1 || len != pub.size())
        return error(openssl_error("cannot extract the public key"));
    return pub;
}

bool verify(const PublicKey& pub, std::span<const std::uint8_t> message, const Signature& sig) {
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!k) {
        ERR_clear_error();
        return false;
    }
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> key(k, &EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, CtxFree> ctx(EVP_MD_CTX_new());
    const bool okay = ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1 &&
                      EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), message.data(), message.size()) == 1;
    ERR_clear_error();
    return okay;
}

}  // namespace dw::ed25519
