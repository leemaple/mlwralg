#pragma once
#include "mlwr/options.hpp"
#include "mlwr/scheme.hpp"

namespace mlwr {
// Research migration of paper 2023/1788, Definitions 3.3/4.1/4.3/4.5,
// to the existing k-dimensional negative-secret phase convention.
struct PairCiphertext {
    Row high, low;
    double scale = 0, bound = 0;
    uint32_t level = 0;
    uint64_t context = 0, key_tag = 0;
};
struct PairTensor {
    TensorCiphertext high, low;
    double scale = 0, bound = 0;
    uint32_t level = 0;
    uint64_t context = 0, key_tag = 0;
};
class CompactScheme {
  public:
    explicit CompactScheme(Profile profile, uint32_t l, uint32_t k);
    const Profile& profile() const { return profile_; }
    uint32_t l() const { return l_; }
    uint32_t k() const { return k_; }
    uint32_t digits() const { return digits_; }
    uint64_t divisor() const { return divisor_; }
    const RnsParams& public_basis() const { return public_; }
    const RnsParams& source_basis() const { return source_; }
    RnsParams basis(uint32_t level) const;
    double encoding_scale() const;
    KeyPair KeyGen() const;
    RelinearizationKey RelinGen(const SecretKey&) const;
    RotationKey RotateKeyGen(const SecretKey&, int64_t) const;
    Plaintext Encode(const Slots&, double bound, double scale = 0) const;
    Plaintext Encode(const Slots& x, uint32_t level, double bound, double scale = 0) const {
        if (level) throw std::invalid_argument("Compact client encoding requires the fresh level");
        return Encode(x, bound, scale);
    }
    Slots Decode(const Plaintext&) const;
    Ciphertext Encrypt(const PublicKey&, const Plaintext&) const;
    PairCiphertext Decompose(const Ciphertext&) const;
    Ciphertext Recombine(const PairCiphertext&) const;
    PairTensor Tensor2(const PairCiphertext&, const PairCiphertext&) const;
    PairCiphertext Relin2(const PairTensor&, const RelinearizationKey&, Row* raised_trace = nullptr,
                         Row* low_trace = nullptr) const;
    PairCiphertext Rescale2(const PairCiphertext&) const;
    PairCiphertext Mult2(const PairCiphertext&, const PairCiphertext&, const RelinearizationKey&) const;
    PairCiphertext Rescale(const Ciphertext& x) const { return Decompose(x); }
    PairCiphertext Rescale(const PairCiphertext& x) const { return Rescale2(x); }
    PairTensor Tensor(const PairCiphertext& a, const PairCiphertext& b) const { return Tensor2(a,b); }
    PairCiphertext Relinearize(const PairTensor& x, const RelinearizationKey& key) const { return Relin2(x,key); }
    PairCiphertext Mult(const PairCiphertext& a, const PairCiphertext& b, const RelinearizationKey& key) const {
        return Relin2(Tensor2(a,b),key);
    }
    PairCiphertext Add(const PairCiphertext&, const PairCiphertext&) const;
    PairCiphertext Rotate(const PairCiphertext&, const RotationKey&) const;
    RingPoly Phase(const SecretKey&, const Ciphertext&) const;
    RingPoly Phase(const SecretKey& key, const PairCiphertext& x) const { return Phase(key, Recombine(x)); }
    RingPoly PhaseRow(const SecretKey&, const Row&, const RnsParams&) const;
    RingPoly PhaseTensor(const SecretKey&, const TensorCiphertext&, const RnsParams&) const;
    Slots Decrypt(const SecretKey&, const Ciphertext&, uint32_t smudge = 0) const;
    Slots Decrypt(const SecretKey& key, const PairCiphertext& ct, uint32_t smudge = 0) const {
        return Decrypt(key, Recombine(ct), smudge);
    }
  private:
    Profile profile_;
    RnsParams public_, source_, div_basis_, evaluation_;
    uint32_t l_, k_, digits_;
    uint64_t divisor_, id_;
    void ValidateRow(const Row&, const RnsParams&) const;
    void ValidateSecret(const SecretKey&) const;
    void Validate(const PairCiphertext&) const;
    void ValidateTensor(const PairTensor&) const;
    void Budget(uint32_t, double, double) const;
    Row MakeRow(const std::vector<RingPoly>&, const RnsParams&, const RingPoly* = nullptr) const;
    std::pair<Row, Row> DecomposeRow(const Row&, const RnsParams&, const RnsParams&) const;
    Row RecombineRow(const Row&, const Row&) const;
    Row Raise(const Row&, const RnsParams&) const;
    TensorCiphertext RawTensor(const Row&, const Row&) const;
    Row Switch(const std::vector<RingPoly>&, const std::vector<Row>&, const RnsParams&, uint32_t, uint32_t) const;
    Row RawRelin(const TensorCiphertext&, const RelinearizationKey&, const RnsParams&) const;
    Row RawSwitch(const Row&, const SwitchingKey&, const RnsParams&) const;
};
int RunCompactExperiment(std::ostream&, const RunOptions&);
} // namespace mlwr
