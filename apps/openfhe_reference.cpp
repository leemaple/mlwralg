#include "openfhe.h"

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
        // All cryptographic settings use upstream defaults. Only the workload's
        // depth and slot count are specified; no manual ring-dimension override.
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(3);
        parameters.SetBatchSize(8);
        auto context = GenCryptoContext(parameters);
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
        auto crypto = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
        std::cout << std::setprecision(17)
                  << "{\n  \"scheme\": \"OpenFHE CKKS reference\",\n"
                  << "  \"openfhe_version\": \"1.6.1\",\n"
                  << "  \"openfhe_commit\": \"b59e1f291965f14fbee5172cd83a20f5b856204f\",\n"
                  << "  \"native_bits\": " << NATIVEINT << ",\n"
                  << "  \"ring_dimension\": " << context->GetRingDimension() << ",\n"
                  << "  \"batch_size\": 8,\n  \"multiplicative_depth\": 3,\n"
                  << "  \"first_mod_bits\": " << parameters.GetFirstModSize() << ",\n"
                  << "  \"scaling_mod_bits\": " << parameters.GetScalingModSize() << ",\n"
                  << "  \"scaling_technique\": \"" << crypto->GetScalingTechnique() << "\",\n"
                  << "  \"security_table\": \"" << crypto->GetStdLevel() << "\",\n"
                  << "  \"rns_primes\": [";
        const auto& towers = crypto->GetElementParams()->GetParams();
        for (std::size_t i = 0; i < towers.size(); ++i) {
            if (i) std::cout << ", ";
            // Strings preserve exact 64-bit values for JSON consumers.
            std::cout << '"' << towers[i]->GetModulus() << '"';
        }
        std::cout << "],\n  \"max_absolute_error\": {\n"
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
