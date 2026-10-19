#include "mlwr/options.hpp"
#include "mlwr/scheme.hpp"
#include <cmath>
#include <functional>
#include <iostream>
#include <stdexcept>

namespace {
using namespace mlwr;
unsigned checks = 0;
double worst_error = 0;
void Require(bool condition) {
    ++checks;
    if (!condition) throw std::runtime_error("Parameter regression failed");
}
void Reject(const std::function<void()>& f) {
    try { f(); } catch (const std::invalid_argument&) { ++checks; return; }
    throw std::runtime_error("Malformed dimension was accepted");
}
void Close(const Slots& actual, const Slots& expected) {
    Require(actual.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        const auto e = std::abs(actual[i] - expected[i]);
        Require(std::isfinite(e) && e <= 0x1p-20);
        worst_error = std::max(worst_error, e);
    }
}
void Trial(uint32_t l, uint32_t k, uint32_t n, uint32_t slots, uint32_t scale_bits) {
    std::cerr << "Parameter trial l=" << l << " k=" << k << " N=" << n << " slots=" << slots << '\n';
    ResearchScheme scheme(OpenFheProfile(1, slots, n, scale_bits), l, k);
    const auto keys = scheme.KeyGen();
    const auto relin = scheme.RelinGen(keys.secret_key);
    Require(keys.secret_key.s.size() == k && keys.public_key.rows.size() == l);
    Require(keys.public_key.rows[0].size() == k + 1 && relin.rows.size() == k * k);
    Slots x(slots), y(slots), sum(slots), product(slots), rotated(slots);
    for (uint32_t i = 0; i < slots; ++i) {
        x[i] = {.125 * (int(i % 7) - 3), .0625 * (int(i % 5) - 2)};
        y[i] = {.25, -.125};
        sum[i] = x[i] + y[i];
        product[i] = x[i] * y[i];
    }
    for (uint32_t i = 0; i < slots; ++i) rotated[i] = x[(i + slots - 1) % slots];
    const auto fresh = scheme.Encrypt(keys.public_key, x);
    Close(scheme.Decrypt(keys.secret_key, fresh), x);
    const auto a = scheme.Rescale(fresh), b = scheme.Rescale(scheme.Encrypt(keys.public_key, y));
    Close(scheme.Decrypt(keys.secret_key, scheme.Add(a, b)), sum);
    const auto tensor = scheme.Tensor(a, b);
    Require(tensor.linear.size() == k + 1 && tensor.quadratic.size() == k * k);
    auto phase = tensor.linear[0];
    for (uint32_t i = 0; i < k; ++i) {
        const auto si = SelectBasis(keys.secret_key.s[i], scheme.basis(a.level));
        phase -= tensor.linear[i + 1] * si;
        for (uint32_t j = 0; j < k; ++j)
            phase += tensor.quadratic[i * k + j] * si * SelectBasis(keys.secret_key.s[j], scheme.basis(a.level));
    }
    Require(phase == scheme.Phase(keys.secret_key, a) * scheme.Phase(keys.secret_key, b));
    Close(scheme.Decrypt(keys.secret_key, scheme.Rescale(scheme.Relinearize(tensor, relin))), product);
    Close(scheme.Decrypt(keys.secret_key, scheme.Rescale(scheme.PlainMult(a, scheme.Encode(y, a.level)))), product);
    const auto other = scheme.KeyGen();
    Close(scheme.Decrypt(other.secret_key, scheme.KeySwitch(a, scheme.KSGen(other.secret_key, keys.secret_key))), x);
    Close(scheme.Decrypt(keys.secret_key, scheme.Rotate(a, scheme.RotateKeyGen(keys.secret_key, -1))), rotated);
    auto bad_secret = keys.secret_key; bad_secret.s.pop_back();
    Reject([&] { scheme.Decrypt(bad_secret, a); });
    auto bad_public = keys.public_key; bad_public.rows.pop_back();
    Reject([&] { scheme.Encrypt(bad_public, x); });
    bad_public = keys.public_key; bad_public.rows[0].pop_back();
    Reject([&] { scheme.Encrypt(bad_public, x); });
    auto bad_ciphertext = a; bad_ciphertext.c.pop_back();
    Reject([&] { scheme.Decrypt(keys.secret_key, bad_ciphertext); });
    auto bad_tensor = tensor; bad_tensor.quadratic.pop_back();
    Reject([&] { scheme.Relinearize(bad_tensor, relin); });
    bad_tensor = tensor; bad_tensor.linear.pop_back();
    Reject([&] { scheme.Relinearize(bad_tensor, relin); });
    auto bad_relin = relin; bad_relin.rows.pop_back();
    Reject([&] { scheme.Relinearize(tensor, bad_relin); });
    bad_relin = relin; bad_relin.rows[0].pop_back();
    Reject([&] { scheme.Relinearize(tensor, bad_relin); });
    auto bad_switch = scheme.KSGen(other.secret_key, keys.secret_key); bad_switch.rows.pop_back();
    Reject([&] { scheme.KeySwitch(a, bad_switch); });
    Reject([&] { ResearchScheme invalid(scheme.profile(), 0, k); });
    Reject([&] { ResearchScheme invalid(scheme.profile(), l, 9); });
}
}  // namespace
int main() {
    try {
        Trial(1, 1, 16384, 4, 50);
        Trial(3, 1, 16384, 16, 48);
        Trial(1, 3, 32768, 8, 50);
        Trial(3, 2, 16384, 1, 50);
        Trial(2, 2, 65536, 8, 50);
        std::cout << "{\"parameter_sets\":5,\"checks\":" << checks
                  << ",\"max_absolute_error\":" << worst_error << ",\"passed\":true}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
