#pragma once

#include "mlwr/profile.hpp"
#include <array>
#include <complex>
#include <vector>

namespace mlwr {
inline constexpr std::size_t k = 2;
inline constexpr std::size_t ell = 2;
using Row = std::array<RingPoly, k + 1>;
using Slots = std::vector<std::complex<double>>;

struct SecretKey {
    std::array<RingPoly, k> s;
    uint64_t context = 0, tag = 0;
};
struct PublicKey {
    std::array<Row, ell> rows;
    uint64_t context = 0, tag = 0;
};
struct KeyPair { PublicKey public_key; SecretKey secret_key; };
struct Plaintext {
    RingPoly polynomial;
    double scale = 0, bound = 0;
    uint32_t level = 0;
    uint64_t context = 0;
};
struct Ciphertext {
    Row c;
    double scale = 0, bound = 0;
    uint32_t level = 0;
    uint64_t context = 0, key_tag = 0;
};
struct RelinearizationKey {
    std::array<Row, k * k> rows;
    uint64_t context = 0, key_tag = 0;
};
struct SwitchingKey {
    std::array<Row, k> rows;
    uint64_t context = 0, source_tag = 0, target_tag = 0;
};
struct RotationKey { SwitchingKey switching; uint32_t exponent = 0; };

// Explicit construction revision: independent source modulus > P*Q and public
// modulus > P. See docs/algorithm.md. Correctness research only, security unproven.
// The engine never calls OpenFHE's encryption, decryption, or evaluation APIs.
class ResearchScheme {
  public:
    explicit ResearchScheme(Profile profile = OpenFheProfile());
    const Profile& profile() const { return profile_; }
    const RnsParams& public_basis() const { return public_; }
    const RnsParams& source_basis() const { return source_; }
    RnsParams basis(uint32_t level) const;
    KeyPair KeyGen() const;
    RelinearizationKey RelinGen(const SecretKey& key) const;
    SwitchingKey KSGen(const SecretKey& target, const SecretKey& source) const;
    RotationKey RotateKeyGen(const SecretKey& key, int64_t steps) const;

    // Bound is a caller-declared, PUBLIC magnitude limit, never inferred from
    // secret inputs. The default limit is |z_i| <= 2. Values are zero-padded.
    Plaintext Encode(const Slots& values, uint32_t level = 0,
                     double public_bound = 2, double scale = 0) const;
    Slots Decode(const Plaintext& plaintext) const;
    Ciphertext Encrypt(const PublicKey& key, const Plaintext& message) const;
    Ciphertext Encrypt(const PublicKey& key, const Slots& message) const;
    // Zero smudging is an explicit correctness diagnostic. Nonzero bounds
    // implement uniform integer flooding, with no IND-CPA^D claim.
    Slots Decrypt(const SecretKey& key, const Ciphertext& ciphertext,
                  uint32_t uniform_smudge_bound = 0) const;
    RingPoly Phase(const SecretKey& key, const Ciphertext& ciphertext) const;
    Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
    Ciphertext PlainMult(const Ciphertext& a, const Plaintext& b) const;
    Ciphertext Mult(const Ciphertext& a, const Ciphertext& b,
                    const RelinearizationKey& key) const;
    Ciphertext Rescale(const Ciphertext& value, uint32_t dropped_towers = 1) const;
    Ciphertext KeySwitch(const Ciphertext& value, const SwitchingKey& key) const;
    Ciphertext Rotate(const Ciphertext& value, const RotationKey& key) const;

  private:
    Profile profile_;
    RnsParams extended_, public_, source_;
    uint64_t id_;
    void Validate(const SecretKey& key) const;
    void Validate(const Ciphertext& value) const;
    void Validate(const Plaintext& value) const;
    void ValidateRows(const std::vector<Row>& rows) const;
    void Budget(uint32_t level, double scale, double bound) const;
    Row MakeRow(const std::array<RingPoly, k>& source_secret,
                const RnsParams& target, const RingPoly* embedding = nullptr) const;
    Row SwitchProduct(const std::vector<RingPoly>& multipliers,
                      const std::vector<Row>& rows, uint32_t level) const;
};
}  // namespace mlwr
