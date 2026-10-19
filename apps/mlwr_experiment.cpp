#include "mlwr/scheme.hpp"
#include "mlwr/options.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
using namespace mlwr;
using Clock = std::chrono::steady_clock;
// Declared before running: approximately the previous 1e-6 acceptance target,
// now an exact binary precision target. This is NOT log2(encoding scale).
unsigned target_bits = 20;
double tolerance = 0x1p-20;
volatile uint64_t observed = 0;
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
double Norm(const RingPoly& poly, bool one = false) {
    double result = 0;
    const auto q = poly.GetParams()->GetModulus();
    for (const auto& x : Coefficients(poly)) {
        const double y = (x > (q >> 1) ? q - x : x).ConvertToDouble();
        result = one ? result + y : std::max(result, y);
    }
    return result;
}
Slots Pointwise(const Slots& a, const Slots& b, bool add = false) {
    Slots out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) out[i] = add ? a[i] + b[i] : a[i] * b[i];
    return out;
}
Slots Shift(const Slots& a, int32_t steps) {
    Slots out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) out[i] = a[(int64_t(i) + steps % int64_t(a.size()) + int64_t(a.size())) % a.size()];
    return out;
}
double Error(const Slots& actual, const Slots& expected) {
    Require(actual.size() == expected.size(), "Slot count mismatch");
    double error = 0;
    for (std::size_t i = 0; i < actual.size(); ++i) {
        Require(std::isfinite(actual[i].real()) && std::isfinite(actual[i].imag()), "Nonfinite output");
        error = std::max(error, std::abs(actual[i] - expected[i]));
    }
    return error;
}
void Values(std::ostream& out, const Slots& values) {
    out << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) out << ',';
        out << '[' << values[i].real() << ',' << values[i].imag() << ']';
    }
    out << ']';
}
void Metric(std::ostream& out, const char* name, const Slots& actual,
            const Slots& expected, double scale, uint32_t level) {
    const auto error = Error(actual, expected);
    if (error > tolerance) {
        std::ostringstream message;
        message << std::setprecision(17) << name << " at level " << level
                << ": decoded error " << error << " exceeds target " << tolerance;
        throw std::runtime_error(message.str());
    }
    out << "{\"operation\":\"" << name << "\",\"level\":" << level
        << ",\"scale\":" << scale << ",\"log2_scale\":" << std::log2(scale)
        << ",\"inverse_scale\":" << 1 / scale << ",\"max_absolute_error\":" << error
        << ",\"error_times_scale\":" << error * scale << ",\"precision_bits\":";
    if (error == 0) out << "null"; else out << -std::log2(error);
    out << ",\"passes_precision_target\":true,\"passes_inverse_scale\":"
        << (error <= 1 / scale ? "true" : "false") << ",\"expected\":";
    Values(out, expected);
    out << ",\"actual\":";
    Values(out, actual);
    out << ",\"slot_absolute_errors\":[";
    for (std::size_t i = 0; i < actual.size(); ++i) {
        if (i) out << ',';
        out << std::abs(actual[i] - expected[i]);
    }
    out << "]}";
}
void BasisJson(std::ostream& out, const RnsParams& basis) {
    // The source basis can exceed double's exponent range at depth 10.
    // Shift the integer first; never emit infinity into JSON.
    const auto bits = basis->GetModulus().GetMSB();
    const auto shift = bits > 53 ? bits - 53 : 0;
    const auto log_modulus = std::log2((basis->GetModulus() >> shift).ConvertToDouble()) + shift;
    out << "{\"modulus\":\"" << basis->GetModulus() << "\",\"bit_length\":"
        << bits << ",\"log2_modulus\":" << log_modulus << ",\"primes\":[";
    for (std::size_t i = 0; i < basis->GetParams().size(); ++i) {
        if (i) out << ',';
        out << '\"' << basis->GetParams()[i]->GetModulus() << '\"';
    }
    out << "]}";
}

Slots Repeat(const Slots& pattern, uint32_t count) {
    Slots result(count);
    for (uint32_t i = 0; i < count; ++i) result[i] = pattern[i % pattern.size()];
    return result;
}

Slots DepthInput(const RunOptions& options, unsigned example) {
    auto values = Repeat({-1., -.999, -.5, 0., .25, .75, .99, 1.}, options.slots);
    std::mt19937 generator(options.message_seed);
    std::uniform_int_distribution<int> draw(-1024, 1024);
    const auto bound = std::min(1., options.message_bound);
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (example == 1) values[i] = std::polar(1., .173 * (i + 1));
        if (example == 2) {
            values[i] = {draw(generator) / 1024., draw(generator) / 1024.};
            values[i] /= std::max(1., std::abs(values[i]));
        }
        values[i] *= bound;
        // Guard against a one-ulp norm overshoot from polar/normalization.
        while (std::abs(values[i]) > bound) values[i] *= std::nextafter(1., 0.);
    }
    return values;
}

void DepthCorrectness(std::ostream& out, const ResearchScheme& scheme, const RunOptions& options,
                      const KeyPair& keys, const RelinearizationKey& relin, unsigned example) {
    const auto input = DepthInput(options, example);
    auto expected = input;
    auto value = scheme.Rescale(scheme.Encrypt(keys.public_key,
        scheme.Encode(input, 0, std::min(1., options.message_bound), options.EncodingScale())));
    out << "{\"circuit\":\"repeated_square\",\"input\":";
    Values(out, input);
    out << ",\"metrics\":[";
    for (unsigned layer = 1; layer <= options.depth; ++layer) {
        std::cerr << "Depth correctness: layer " << layer << '/' << options.depth << '\n';
        value = scheme.Rescale(scheme.Mult(value, value, relin));
        expected = Pointwise(expected, expected);
        if (layer > 1) out << ',';
        Metric(out, "depth_square", scheme.Decrypt(keys.secret_key, value, options.smudge_bound),
               expected, value.scale, value.level);
    }
    out << "]}";
}

void Correctness(std::ostream& out, const ResearchScheme& scheme, const RunOptions& options) {
    const auto decrypt = [&](const SecretKey& key, const Ciphertext& c) {
        return scheme.Decrypt(key, c, options.smudge_bound);
    };
    const Slots reals{-1.25, -.125, 0, .125, .5, 1, 1.25, 2};
    const Slots factors{.5, -.25, 1.5, -1, .125, .75, -1.25, .5};
    const Slots complex{{.25,.125}, {-.5,.25}, {0,0}, {.125,-.0625},
                        {.5,-.5}, {1,.25}, {-.25,-.5}, {1.5,.125}};
    const Slots complex_factors{{-.5,.25}, {.25,-.5}, {1,.25}, {-.125,.5},
                                {.5,.5}, {-.25,.125}, {.25,1}, {.5,-.25}};
    std::mt19937 generator(options.message_seed);  // Public messages only; never secret-key randomness.
    std::uniform_int_distribution<int> draw(-1024, 1024);
    out << '[';
    bool first = true;
    for (unsigned trial = 0; trial < options.key_trials; ++trial) {
        std::cerr << "Correctness: fresh key trial " << trial + 1 << "/" << options.key_trials << "\n";
        const auto keys = scheme.KeyGen();
        const auto relin = scheme.RelinGen(keys.secret_key);
        double rounding_bound = .5;
        for (const auto& s : keys.secret_key.s) rounding_bound += .5 * Norm(s, true);
        const double fresh_bound = rounding_bound * (1 + double(scheme.l()) * scheme.profile().ciphertext->GetRingDimension() *
            scheme.basis(0)->GetModulus().ConvertToDouble() / scheme.public_basis()->GetModulus().ConvertToDouble());
        for (unsigned example = 0; example < 3; ++example) {
            Slots x = Repeat(example == 0 ? reals : complex, scheme.profile().slots);
            Slots y = Repeat(example == 0 ? factors : complex_factors, scheme.profile().slots);
            if (example == 2) for (unsigned i = 0; i < x.size(); ++i) {
                x[i] = {draw(generator) / 1024., draw(generator) / 1024.};
                y[i] = {draw(generator) / 1024., draw(generator) / 1024.};
            }
            for (auto& value : x) value *= options.message_bound / 2;
            for (auto& value : y) value *= options.message_bound / 2;
            const auto px = scheme.Encode(x, 0, options.message_bound, options.EncodingScale());
            const auto py = scheme.Encode(y, 0, options.message_bound, options.EncodingScale());
            const auto cx = scheme.Encrypt(keys.public_key, px), cy = scheme.Encrypt(keys.public_key, py);
            const double fresh_x_noise = Norm(scheme.Phase(keys.secret_key, cx) - px.polynomial);
            const double fresh_y_noise = Norm(scheme.Phase(keys.secret_key, cy) - py.polynomial);
            Require(fresh_x_noise <= fresh_bound && fresh_y_noise <= fresh_bound, "Fresh coefficient noise bound");
            // FLEXIBLEAUTOEXT preparation is recorded separately from the
            // THREE multiplication stages; both inputs are now at level 1.
            const auto a = scheme.Rescale(cx), b = scheme.Rescale(cy);
            const auto tensor = scheme.Tensor(a, b);
            auto tensor_phase = tensor.linear[0];
            std::vector<RingPoly> secrets;
            for (const auto& secret : keys.secret_key.s)
                secrets.push_back(SelectBasis(secret, scheme.basis(a.level)));
            for (uint32_t i = 0; i < scheme.k(); ++i) {
                tensor_phase -= tensor.linear[i + 1] * secrets[i];
                for (uint32_t j = 0; j < scheme.k(); ++j)
                    tensor_phase += tensor.quadratic[i * scheme.k() + j] * secrets[i] * secrets[j];
            }
            const auto expected_phase = scheme.Phase(keys.secret_key, a) * scheme.Phase(keys.secret_key, b);
            Require(tensor_phase == expected_phase, "Tensor phase identity failed");
            const auto relinearized = scheme.Relinearize(tensor, relin);
            const double relin_noise = Norm(scheme.Phase(keys.secret_key, relinearized) - expected_phase);
            const double relin_bound = rounding_bound * (1 + double(scheme.k() * scheme.k()) * scheme.profile().ciphertext->GetRingDimension() *
                scheme.basis(a.level)->GetModulus().ConvertToDouble() /
                (2 * scheme.profile().auxiliary->GetModulus().ConvertToDouble()));
            Require(relin_noise <= relin_bound, "Relinearization coefficient noise bound");
            const auto product = scheme.Rescale(relinearized);
            const double rescale_noise = Norm(scheme.Phase(keys.secret_key, product) -
                ScaleAndRound(scheme.Phase(keys.secret_key, relinearized), scheme.basis(product.level)));
            Require(rescale_noise <= rounding_bound + .5, "Rescale coefficient noise bound");
            if (!first) out << ',';
            first = false;
            out << "{\"trial\":" << trial + 1 << ",\"case\":\""
                << (example == 0 ? "real" : example == 1 ? "complex" : "dyadic_random") << "\",\"metrics\":[";
            Metric(out, "decode_encode_a", scheme.Decode(px), x, px.scale, px.level); out << ',';
            Metric(out, "decrypt_fresh_a", decrypt(keys.secret_key, cx), x, cx.scale, cx.level); out << ',';
            Metric(out, "decrypt_fresh_b", decrypt(keys.secret_key, cy), y, cy.scale, cy.level); out << ',';
            Metric(out, "decrypt_prepared_a", decrypt(keys.secret_key, a), x, a.scale, a.level); out << ',';
            Metric(out, "decrypt_prepared_b", decrypt(keys.secret_key, b), y, b.scale, b.level); out << ',';
            const auto expected = Pointwise(x, y);
            Metric(out, "multiply_before_rescale", decrypt(keys.secret_key, relinearized), expected,
                   relinearized.scale, relinearized.level); out << ',';
            Metric(out, "multiply_after_rescale", decrypt(keys.secret_key, product), expected,
                   product.scale, product.level);
            out << "],\"depth_circuit\":";
            DepthCorrectness(out, scheme, options, keys, relin, example);
            out << ",\"coefficient_checks\":{\"tensor_identity\":true,\"fresh_a\":" << fresh_x_noise
                << ",\"fresh_b\":" << fresh_y_noise << ",\"fresh_bound\":" << fresh_bound
                << ",\"relinearize\":" << relin_noise << ",\"relinearize_bound\":" << relin_bound
                << ",\"rescale\":" << rescale_noise << ",\"rescale_bound\":" << rounding_bound + .5
                << ",\"all_passed\":true}}";
        }
    }
    out << ']';
}

using Measurements = std::map<std::string, std::vector<double>>;
double Milliseconds(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}
template<class Operation, class Verify>
void Measure(Measurements& results, const std::string& name, unsigned warmups, unsigned samples,
             Operation operation, Verify verify) {
    std::cerr << "Timing: " << name << '\n';
    for (unsigned i = 0; i < warmups + samples; ++i) {
        const auto start = Clock::now();
        const auto result = operation();
        const auto end = Clock::now();
        verify(result);  // Decryption, comparison and reporting are outside the measured interval.
        if (i >= warmups) results[name].push_back(Milliseconds(start, end));
    }
}
void Benchmark(std::ostream& out, const ResearchScheme& scheme, const RunOptions& options) {
    const auto decrypt = [&](const SecretKey& key, const Ciphertext& c) {
        return scheme.Decrypt(key, c, options.smudge_bound);
    };
    const auto samples = options.samples, warmups = options.warmups;
    auto x = Repeat({-.75, -.125, 0, .125, .5, 1, 1.25, 1.5}, scheme.profile().slots);
    auto y = Repeat({.5, -.25, 1.5, -1, .125, .75, -1.25, .5}, scheme.profile().slots);
    for (auto& value : x) value *= options.message_bound / 2;
    for (auto& value : y) value *= options.message_bound / 2;
    const auto keys = scheme.KeyGen();
    const auto relin = scheme.RelinGen(keys.secret_key);
    const auto rotation = scheme.RotateKeyGen(keys.secret_key, options.rotation_steps);
    const auto plaintext = scheme.Encode(x, 0, options.message_bound, options.EncodingScale());
    const auto fresh = scheme.Encrypt(keys.public_key, plaintext);
    const auto a = scheme.Rescale(fresh);
    const auto b = scheme.Rescale(scheme.Encrypt(keys.public_key, scheme.Encode(y, 0, options.message_bound, options.EncodingScale())));
    const auto product = scheme.Rescale(scheme.Mult(a, b, relin));
    Measurements results;
    auto verify_slots = [&](const Slots& actual, const Slots& expected) {
        Require(Error(actual, expected) <= tolerance, "Timing sample correctness failed");
    };
    Measure(results, "keygen", warmups, samples, [&] { return scheme.KeyGen(); }, [&](const KeyPair& v) {
        verify_slots(decrypt(v.secret_key, scheme.Encrypt(v.public_key, plaintext)), x);
    });
    Measure(results, "relin_keygen", warmups, samples, [&] { return scheme.RelinGen(keys.secret_key); },
        [&](const RelinearizationKey& v) { observed += v.key_tag; });
    Measure(results, "rotation_keygen", warmups, samples, [&] { return scheme.RotateKeyGen(keys.secret_key, options.rotation_steps); },
        [&](const RotationKey& v) { observed += v.exponent; });
    Measure(results, "encode", warmups, samples, [&] { return scheme.Encode(x, 0, options.message_bound, options.EncodingScale()); },
        [&](const Plaintext& v) { verify_slots(scheme.Decode(v), x); });
    Measure(results, "encrypt_preencoded", warmups, samples, [&] { return scheme.Encrypt(keys.public_key, plaintext); },
        [&](const Ciphertext& v) { verify_slots(decrypt(keys.secret_key, v), x); });
    Measure(results, "decrypt_decode_fresh", warmups, samples, [&] { return decrypt(keys.secret_key, fresh); },
        [&](const Slots& v) { verify_slots(v, x); });
    Measure(results, "prepare_one_ciphertext", warmups, samples, [&] { return scheme.Rescale(fresh); },
        [&](const Ciphertext& v) { verify_slots(decrypt(keys.secret_key, v), x); });
    Measure(results, "add", warmups, samples, [&] { return scheme.Add(a, b); },
        [&](const Ciphertext& v) { verify_slots(decrypt(keys.secret_key, v), Pointwise(x, y, true)); });
    Measure(results, "rotate", warmups, samples, [&] { return scheme.Rotate(a, rotation); },
        [&](const Ciphertext& v) { verify_slots(decrypt(keys.secret_key, v), Shift(x, options.rotation_steps)); });
    Measure(results, "decrypt_decode_product", warmups, samples, [&] { return decrypt(keys.secret_key, product); },
        [&](const Slots& v) { verify_slots(v, Pointwise(x, y)); });
    const auto depth_input = DepthInput(options, 1);
    const auto depth_prepared = scheme.Rescale(scheme.Encrypt(keys.public_key,
        scheme.Encode(depth_input, 0, std::min(1., options.message_bound), options.EncodingScale())));
    auto depth_expected = depth_input;
    for (unsigned layer = 0; layer < options.depth; ++layer)
        depth_expected = Pointwise(depth_expected, depth_expected);
    Measure(results, "depth_square_circuit", warmups, samples, [&] {
        auto value = depth_prepared;
        for (unsigned layer = 0; layer < options.depth; ++layer)
            value = scheme.Rescale(scheme.Mult(value, value, relin));
        return value;
    }, [&](const Ciphertext& v) { verify_slots(decrypt(keys.secret_key, v), depth_expected); });
    std::cerr << "Timing: tensor -> relinearize -> rescale, same invocation\n";
    for (unsigned i = 0; i < warmups + samples; ++i) {
        const auto t0 = Clock::now();
        const auto tensor = scheme.Tensor(a, b);
        const auto t1 = Clock::now();
        const auto relinearized = scheme.Relinearize(tensor, relin);
        const auto t2 = Clock::now();
        const auto scaled = scheme.Rescale(relinearized);
        const auto t3 = Clock::now();
        verify_slots(decrypt(keys.secret_key, scaled), Pointwise(x, y));
        if (i >= warmups) {
            results["multiply_tensor"].push_back(Milliseconds(t0, t1));
            results["multiply_relinearize"].push_back(Milliseconds(t1, t2));
            results["multiply_rescale"].push_back(Milliseconds(t2, t3));
            results["multiply_total"].push_back(Milliseconds(t0, t3));
        }
    }
    out << '{';
    bool first = true;
    for (const auto& item : results) {
        if (!first) out << ',';
        first = false;
        auto sorted = item.second;
        std::sort(sorted.begin(), sorted.end());
        const double mean = std::accumulate(sorted.begin(), sorted.end(), 0.) / sorted.size();
        double variance = 0;
        for (const auto x : sorted) variance += (x - mean) * (x - mean);
        const double median = sorted.size() % 2 ? sorted[sorted.size() / 2] :
            .5 * (sorted[sorted.size() / 2 - 1] + sorted[sorted.size() / 2]);
        out << '\"' << item.first << "\":{\"mean_ms\":" << mean << ",\"median_ms\":" << median
            << ",\"min_ms\":" << sorted.front() << ",\"max_ms\":" << sorted.back()
            << ",\"stddev_sample_ms\":" << std::sqrt(variance / (sorted.size() - 1))
            << ",\"p95_nearest_rank_ms\":" << sorted[std::size_t(std::ceil(.95 * sorted.size())) - 1]
            << ",\"samples_ms\":[";
        for (std::size_t i = 0; i < item.second.size(); ++i) {
            if (i) out << ',';
            out << item.second[i];
        }
        out << "]}";
    }
    out << '}';
}
}  // namespace

int main(int argc, char** argv) {
    try {
        const auto options = ParseOptions(argc, argv, true);
        if (options.help) { PrintOptionsHelp(std::cout, true); return 0; }
        const auto samples = options.samples, warmups = options.warmups;
        target_bits = options.precision_bits;
        tolerance = std::ldexp(1.0, -int(target_bits));
        const ResearchScheme scheme(options.MakeProfile(), options.l, options.k);
        std::ostringstream report;
        report << std::setprecision(17) << "{\"schema_version\":3,\"algorithm\":\"revised research construction\","
            << "\"security\":\"unproven\",\"bootstrap\":false,\"l\":" << scheme.l()
            << ",\"k\":" << scheme.k() << ",\"requested_parameters\":";
        WriteOptionsJson(report, options);
        report << ",\"profile\":";
        WriteProfileJson(report, scheme.profile());
        report << ",\"moduli\":{\"P_main\":"; BasisJson(report, scheme.basis(0));
        report << ",\"Q_auxiliary\":"; BasisJson(report, scheme.profile().auxiliary);
        report << ",\"T_public\":"; BasisJson(report, scheme.public_basis());
        report << ",\"W_source\":"; BasisJson(report, scheme.source_basis());
        report << '}';
        if (options.print_parameters) { std::cout << report.str() << "}\n"; return 0; }
        report << ",\"protocol\":{\"precision_target_bits\":" << target_bits << ",\"absolute_tolerance\":"
            << tolerance << ",\"target_origin\":\"configured absolute-error target, not log2(scale)\","
            << "\"fresh_key_trials\":" << options.key_trials << ",\"cases_per_key\":3,\"samples_per_operation\":" << samples
            << ",\"warmups_per_operation\":" << warmups << ",\"clock\":\"steady_clock\","
            << "\"timing_unit\":\"milliseconds per call over " << scheme.profile().slots << " slots\",\"smudge_bound\":" << options.smudge_bound
            << ",\"rotation_steps\":" << options.rotation_steps << "},\"correctness\":";
        Correctness(report, scheme, options);
        std::cerr << "Correctness gate passed; beginning timed operations\n";
        report << ",\"timings\":";
        Benchmark(report, scheme, options);
        report << ",\"all_correctness_checks_passed\":true}\n";
        std::cout << report.str();
    } catch (const std::exception& error) {
        std::cerr << "Experiment failed: " << error.what() << '\n';
        return 1;
    }
}
