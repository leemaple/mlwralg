#include "mlwr/options.hpp"

#include <fstream>
#include <cmath>
#include <iomanip>
#include <limits>
#include <map>
#include <ostream>
#include <set>
#include <stdexcept>
#include <vector>

namespace mlwr {
namespace {
std::string Trim(const std::string& text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    return first == std::string::npos ? "" : text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}
uint32_t ParseUnsigned(const std::string& text) {
    if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
        throw std::invalid_argument("Expected an unsigned decimal integer, got: " + text);
    const auto value = std::stoull(text);
    if (value > std::numeric_limits<uint32_t>::max()) throw std::invalid_argument("Integer is too large");
    return static_cast<uint32_t>(value);
}
std::string Key(std::string key) {
    if (key == "n" || key == "ring-dim") return "N";
    for (auto& c : key) if (c == '-') c = '_';
    return key;
}
void Set(RunOptions& options, const std::string& name, const std::string& value) {
    if (Key(name) == "message_bound") {
        std::size_t consumed = 0;
        options.message_bound = std::stod(value, &consumed);
        if (consumed != value.size()) throw std::invalid_argument("message_bound must be a number");
        return;
    }
    if (Key(name) == "rotation_steps") {
        const bool negative = !value.empty() && value[0] == '-';
        const auto magnitude = ParseUnsigned(negative ? value.substr(1) : value);
        if (magnitude > 65536) throw std::invalid_argument("rotation_steps must be in -65536..65536");
        options.rotation_steps = negative ? -int32_t(magnitude) : int32_t(magnitude);
        return;
    }
    const std::map<std::string, uint32_t*> fields{
        {"l", &options.l}, {"k", &options.k}, {"N", &options.n}, {"depth", &options.depth},
        {"slots", &options.slots}, {"scale_bits", &options.scale_bits},
        {"first_mod_bits", &options.first_mod_bits}, {"samples", &options.samples}, {"warmups", &options.warmups},
        {"security_bits", &options.security_bits}, {"precision_bits", &options.precision_bits},
        {"key_trials", &options.key_trials}, {"message_seed", &options.message_seed},
        {"smudge_bound", &options.smudge_bound}, {"initial_scale_bits", &options.initial_scale_bits}};
    const auto found = fields.find(Key(name));
    if (found == fields.end()) throw std::invalid_argument("Unknown parameter: " + name);
    *found->second = ParseUnsigned(value);
}
void ReadConfig(RunOptions& options, const std::string& path) {
    std::ifstream stream(path);
    if (!stream) throw std::invalid_argument("Cannot open config: " + path);
    std::set<std::string> seen;
    std::string line;
    unsigned number = 0;
    while (std::getline(stream, line)) {
        ++number;
        if (number == 1 && line.compare(0, 3, "\xef\xbb\xbf") == 0) line.erase(0, 3);
        line = Trim(line.substr(0, line.find('#')));
        if (line.empty()) continue;
        const auto separator = line.find('=');
        if (separator == std::string::npos)
            throw std::invalid_argument("Expected key=value in " + path + ":" + std::to_string(number));
        const auto key = Key(Trim(line.substr(0, separator)));
        if (!seen.insert(key).second) throw std::invalid_argument("Duplicate config parameter: " + key);
        Set(options, key, Trim(line.substr(separator + 1)));
    }
    if (stream.bad()) throw std::runtime_error("Cannot read config: " + path);
}
}  // namespace

Profile RunOptions::MakeProfile() const {
    return OpenFheProfile(depth, slots, n, scale_bits, first_mod_bits, security_bits);
}
double RunOptions::EncodingScale() const {
    return initial_scale_bits ? std::ldexp(1.0, int(initial_scale_bits)) : 0;
}
RunOptions ParseOptions(int argc, char** argv, bool experiment) {
    RunOptions options;
    std::string config;
    std::vector<std::pair<std::string, std::string>> overrides;
    std::vector<std::string> positional;
    std::set<std::string> seen;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h") { options.help = true; continue; }
        if (arg == "--print-parameters") { options.print_parameters = true; continue; }
        if (arg.rfind("--", 0) != 0) { positional.push_back(arg); continue; }
        auto key = Key(arg.substr(2));
        if (!seen.insert(key).second) throw std::invalid_argument("Duplicate command option: " + arg);
        if (++i >= argc) throw std::invalid_argument("Missing value for " + arg);
        if (key == "config") {
            config = argv[i];
            if (config.empty()) throw std::invalid_argument("Config path is empty");
        }
        else overrides.emplace_back(key, argv[i]);
    }
    if (options.help) return options;
    if ((!experiment && !positional.empty()) || positional.size() > 2)
        throw std::invalid_argument("Unexpected positional arguments; use --help");
    if (!config.empty()) ReadConfig(options, config);
    if (!positional.empty()) {
        if (seen.count("samples") || seen.count("warmups"))
            throw std::invalid_argument("Do not mix positional and named timing arguments");
        options.samples = ParseUnsigned(positional[0]);
        if (positional.size() == 2) options.warmups = ParseUnsigned(positional[1]);
    }
    for (const auto& item : overrides) Set(options, item.first, item.second);
    if (options.l < 1 || options.l > 8 || options.k < 1 || options.k > 8)
        throw std::invalid_argument("l and k must independently be in 1..8");
    ValidateProfileOptions(options.depth, options.slots, options.n, options.scale_bits,
                           options.first_mod_bits, options.security_bits);
    if (options.samples < 3 || options.samples > 1000 || options.warmups < 1 || options.warmups > 100)
        throw std::invalid_argument("samples must be 3..1000; warmups must be 1..100");
    if (options.precision_bits < 1 || options.precision_bits > 50 || options.key_trials < 1 || options.key_trials > 100)
        throw std::invalid_argument("precision_bits must be 1..50; key_trials must be 1..100");
    if (!std::isfinite(options.message_bound) || options.message_bound <= 0 || options.message_bound > 1024)
        throw std::invalid_argument("message_bound must be finite and in (0,1024]");
    if (options.smudge_bound > (1u << 30)) throw std::invalid_argument("smudge_bound must be 0..1073741824");
    if (options.initial_scale_bits && (options.initial_scale_bits < 40 || options.initial_scale_bits > 100))
        throw std::invalid_argument("initial_scale_bits must be 0 (automatic) or 40..100");
    return options;
}

void WriteOptionsJson(std::ostream& out, const RunOptions& o) {
    out << std::setprecision(17) << "{\"l\":" << o.l << ",\"k\":" << o.k << ",\"N\":" << o.n
        << ",\"depth\":" << o.depth << ",\"slots\":" << o.slots
        << ",\"scale_bits\":" << o.scale_bits << ",\"first_mod_bits\":" << o.first_mod_bits
        << ",\"samples\":" << o.samples << ",\"warmups\":" << o.warmups
        << ",\"security_bits\":" << o.security_bits << ",\"precision_bits\":" << o.precision_bits
        << ",\"key_trials\":" << o.key_trials << ",\"message_seed\":" << o.message_seed
        << ",\"message_bound\":" << o.message_bound << ",\"smudge_bound\":" << o.smudge_bound
        << ",\"initial_scale_bits\":" << o.initial_scale_bits
        << ",\"rotation_steps\":" << o.rotation_steps << '}';
}
void PrintOptionsHelp(std::ostream& out, bool experiment) {
    out << "Usage: " << (experiment ? "mlwr_experiment" : "mlwr_demo") << " [options]\n"
        << "  --config FILE           UTF-8 key=value file; # starts a comment\n"
        << "  --l INT --k INT         Independent module dimensions, 1..8 (default 2,2)\n"
        << "  --n INT                 N=0 auto, or power of two 1024..131072; security check retained\n"
        << "  --depth INT             Multiplicative depth 1..6 (default 3)\n"
        << "  --slots INT             Power of two, <= N/2 (default 8)\n"
        << "  --scale-bits INT        Scaling modulus bits 41..59 (default 50)\n"
        << "  --first-mod-bits INT    scale_bits < value <= 60 (default 60)\n"
        << "  --samples INT           Timing samples 3..1000 (default 15)\n"
        << "  --warmups INT           Timing warmups 1..100 (default 2)\n"
        << "  --security-bits INT     OpenFHE RLWE table: 128, 192, 256 (default 128)\n"
        << "  --precision-bits INT    Absolute error target 2^-bits, 1..50 (default 20)\n"
        << "  --key-trials INT        Independent experiment keys 1..100 (default 3)\n"
        << "  --message-seed INT      Public experiment messages only, uint32 (default 20261013)\n"
        << "  --message-bound NUMBER  Public input magnitude bound (0,1024] (default 2)\n"
        << "  --smudge-bound INT      Uniform integer decryption noise 0..2^30 (default 0)\n"
        << "  --rotation-steps INT    Positive left, negative right, -65536..65536 (default 1)\n"
        << "  --initial-scale-bits INT  Initial Delta=2^bits; 0 auto or 40..100 (default 0)\n"
        << "  --print-parameters      Print resolved settings and actual profile, without key generation\n"
        << "Priority: defaults < config < command options (regardless of argument order).\n";
}
}  // namespace mlwr
