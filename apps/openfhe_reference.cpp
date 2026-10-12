#include "mlwr/profile.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace lbcrypto;

double Check(const CryptoContext<DCRTPoly>& context, const PrivateKey<DCRTPoly>& key,
             const Ciphertext<DCRTPoly>& ciphertext, const std::vector<double>& expected) {
    Plaintext result;
    context->Decrypt(key, ciphertext, &result);
    result->SetLength(expected.size());
    const auto actual = result->GetRealPackedValue();
    if (actual.size() != expected.size()) {
        throw std::runtime_error("Unexpected decoded slot count");
    }
    double error = 0;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (!std::isfinite(actual[i])) {
            throw std::runtime_error("Non-finite decrypted result");
        }
        error = std::max(error, std::abs(actual[i] - expected[i]));
    }
    if (error > 1e-6) {
        throw std::runtime_error("CKKS reference error exceeds 1e-6: " + std::to_string(error));
    }
    return error;
}
}  // namespace

int main() {
    try {
        using namespace lbcrypto;
        const auto profile = mlwr::OpenFheProfile();
        auto context = profile.encoder;
        context->Enable(PKE);
        context->Enable(KEYSWITCH);
        context->Enable(LEVELEDSHE);
        auto keys = context->KeyGen();
        context->EvalMultKeyGen(keys.secretKey);
        const std::vector<double> input{-1.25, -0.125, 0.0, 0.125, 0.5, 1.0, 1.25, 2.0};
        auto encoded = context->MakeCKKSPackedPlaintext(input);
        auto ciphertext = context->Encrypt(keys.publicKey, encoded);
        std::vector<double> sum, square, fourth;
        for (double x : input) {
            sum.push_back(2 * x);
            square.push_back(x * x);
            fourth.push_back(x * x * x * x);
        }
        const double roundtrip = Check(context, keys.secretKey, ciphertext, input);
        const double addition = Check(context, keys.secretKey, context->EvalAdd(ciphertext, ciphertext), sum);
        auto squared = context->EvalMult(ciphertext, ciphertext);
        const double multiplication = Check(context, keys.secretKey, squared, square);
        const double chain = Check(context, keys.secretKey, context->EvalMult(squared, squared), fourth);
        std::cout << std::setprecision(17)
                  << "{\n  \"scheme\": \"OpenFHE CKKS reference\",\n  \"profile\": ";
        mlwr::WriteProfileJson(std::cout, profile);
        std::cout << ",\n  \"max_absolute_error\": {\n"
                  << "    \"roundtrip\": " << roundtrip << ",\n"
                  << "    \"addition\": " << addition << ",\n"
                  << "    \"multiplication\": " << multiplication << ",\n"
                  << "    \"fourth_power\": " << chain << "\n  }\n}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Reference check failed: " << error.what() << '\n';
        return 1;
    }
}
