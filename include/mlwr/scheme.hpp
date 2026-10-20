#pragma once

#include "mlwr/profile.hpp"
#include <complex>
#include <vector>

namespace mlwr {
using Row = std::vector<RingPoly>;
using Slots = std::vector<std::complex<double>>;

struct SecretKey {
    std::vector<RingPoly> s;
    uint64_t context = 0, tag = 0;
};
struct PublicKey {
    std::vector<Row> rows;
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
// Tensor stage output: k+1 linear and k*k quadratic terms.
// Phase = linear[0] - sum(linear[j+1]*s[j]) + sum(quadratic[i*k+j]*s[i]*s[j]).
struct TensorCiphertext {
    Row linear;
    std::vector<RingPoly> quadratic;
    double scale = 0, bound = 0;
    uint32_t level = 0;
    uint64_t context = 0, key_tag = 0;
};
struct RelinearizationKey {
    std::vector<Row> rows;
    uint64_t context = 0, key_tag = 0;
};
struct SwitchingKey {
    std::vector<Row> rows;
    uint64_t context = 0, source_tag = 0, target_tag = 0;
    uint32_t digit_bits = 0, digit_count = 0;
};
struct RotationKey { SwitchingKey switching; uint32_t exponent = 0; };

// Explicit construction revision: independent source modulus > P*Q and public
// modulus > P. See docs/algorithm.md. Correctness research only, security unproven.
// The engine never calls OpenFHE's encryption, decryption, or evaluation APIs.
class ResearchScheme {
  public:
    explicit ResearchScheme(Profile profile = OpenFheProfile(), uint32_t l = 2, uint32_t k = 2);
    uint32_t l() const { return l_; }
    uint32_t k() const { return k_; }
    uint64_t context_id() const { return id_; }
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
    Slots DecodeAll(const Plaintext& plaintext) const;
    Ciphertext Encrypt(const PublicKey& key, const Plaintext& message) const;
    Ciphertext Encrypt(const PublicKey& key, const Slots& message) const;
    // Zero smudging is an explicit correctness diagnostic. Nonzero bounds
    // implement uniform integer flooding, with no IND-CPA^D claim.
    Slots Decrypt(const SecretKey& key, const Ciphertext& ciphertext,
                  uint32_t uniform_smudge_bound = 0) const;
    RingPoly Phase(const SecretKey& key, const Ciphertext& ciphertext) const;
    Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
    Ciphertext PlainMult(const Ciphertext& a, const Plaintext& b) const;
    // The three multiplication stages are Tensor -> Relinearize -> Rescale.
    // Mult remains the compatibility entry point for the first two stages.
    TensorCiphertext Tensor(const Ciphertext& a, const Ciphertext& b) const;
    Ciphertext Relinearize(const TensorCiphertext& tensor,
                          const RelinearizationKey& key) const;
    Ciphertext Mult(const Ciphertext& a, const Ciphertext& b,
                    const RelinearizationKey& key) const;
    Ciphertext Rescale(const Ciphertext& value, uint32_t dropped_towers = 1) const;
    Ciphertext KeySwitch(const Ciphertext& value, const SwitchingKey& key) const;
    Ciphertext Rotate(const Ciphertext& value, const RotationKey& key) const;

  private:
    Profile profile_;
    uint32_t l_, k_;
    RnsParams extended_, public_, source_;
    uint64_t id_;
    uint32_t key_digits_ = 1;
    void Validate(const SecretKey& key) const;
    void Validate(const Ciphertext& value) const;
    void Validate(const Plaintext& value) const;
    void ValidateRows(const std::vector<Row>& rows) const;
    void Budget(uint32_t level, double scale, double bound) const;
    Row MakeRow(const std::vector<RingPoly>& source_secret,
                const RnsParams& target, const RingPoly* embedding = nullptr) const;
    Row SwitchProduct(const std::vector<RingPoly>& multipliers,
                      const std::vector<Row>& rows, uint32_t level) const;
};
}  // namespace mlwr
