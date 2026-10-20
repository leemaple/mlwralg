#pragma once

#include "mlwr/scheme.hpp"

namespace mlwr {
// Balanced global-integer digits, not OpenFHE's per-tower BV decomposition.
// All digit products accumulate in Q_l P before one coefficient-wise /P round.
Row GadgetSwitch(const std::vector<RingPoly>& multipliers, const std::vector<Row>& rows,
                 const RnsParams& target, const RnsParams& key_basis,
                 const RnsParams& auxiliary, uint32_t columns,
                 uint32_t digit_bits, uint32_t digit_count);
}
