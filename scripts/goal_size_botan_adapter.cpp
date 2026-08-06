extern "C" {
#include "goal_size_adapter.h"
}

#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_keys.h>
#include <botan/internal/ml_kem_impl.h>
#include <botan/rng.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <utility>

static_assert(GOAL_MLKEM768_KEYPAIR_COINS_BYTES ==
              2 * Botan::KyberConstants::SEED_BYTES);
static_assert(GOAL_MLKEM768_ENCAPS_COINS_BYTES ==
              Botan::KyberConstants::SEED_BYTES);
static_assert(GOAL_MLKEM768_SHARED_SECRET_BYTES ==
              Botan::KyberConstants::SHARED_KEY_BYTES);

namespace {
class FixedInputRng final : public Botan::RandomNumberGenerator {
 public:
  explicit FixedInputRng(std::span<const uint8_t> input) : input_(input) {}

  bool accepts_input() const override { return false; }
  bool is_seeded() const override { return valid_; }
  std::string name() const override { return "goal-fixed-input"; }
  void clear() noexcept override {
    offset_ = input_.size();
    valid_ = false;
  }

  bool consumed_exactly() const {
    return valid_ && offset_ == input_.size();
  }

 private:
  void fill_bytes_with_input(std::span<uint8_t> output,
                             std::span<const uint8_t> input) override {
    if (!input.empty() || !valid_ || offset_ > input_.size() ||
        output.size() > input_.size() - offset_) {
      std::fill(output.begin(), output.end(), 0);
      valid_ = false;
      return;
    }
    if (!output.empty()) {
      std::copy_n(input_.data() + offset_, output.size(), output.data());
      offset_ += output.size();
    }
  }

  std::span<const uint8_t> input_;
  size_t offset_ = 0;
  bool valid_ = true;
};

Botan::KyberConstants mlkem768_constants() {
  return Botan::KyberConstants(
      Botan::KyberMode(Botan::KyberMode::ML_KEM_768));
}

template <typename Container>
bool copy_exact(uint8_t *output, const Container &input, size_t expected) {
  if (input.size() != expected) {
    return false;
  }
  std::memcpy(output, input.data(), expected);
  return true;
}
}  // namespace

extern "C" int goal_mlkem768_keypair_derand(uint8_t *ek, uint8_t *dk,
                                              const uint8_t *coins) {
  try {
    auto keypair = Botan::Seed_Expanding_Keypair_Codec().decode_keypair(
        std::span<const uint8_t>(coins, GOAL_MLKEM768_KEYPAIR_COINS_BYTES),
        mlkem768_constants());
    const auto private_key =
        Botan::Expanded_Keypair_Codec().encode_keypair(keypair);
    const auto &public_key = keypair.first->public_key_bits_raw().get();
    return copy_exact(ek, public_key, GOAL_MLKEM768_PUBLIC_KEY_BYTES) &&
                   copy_exact(dk, private_key, GOAL_MLKEM768_SECRET_KEY_BYTES)
               ? 0
               : 1;
  } catch (...) {
    return 1;
  }
}

extern "C" int goal_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss,
                                             const uint8_t *ek,
                                             const uint8_t *coins) {
  try {
    auto public_key = std::make_shared<Botan::Kyber_PublicKeyInternal>(
        mlkem768_constants(),
        Botan::KyberSerializedPublicKey(std::span<const uint8_t>(
            ek, GOAL_MLKEM768_PUBLIC_KEY_BYTES)));
    Botan::ML_KEM_Encryptor operation(std::move(public_key), "Raw");
    FixedInputRng rng{std::span<const uint8_t>(
        coins, GOAL_MLKEM768_ENCAPS_COINS_BYTES)};
    operation.raw_kem_encrypt(
        std::span<uint8_t>(ct, GOAL_MLKEM768_CIPHERTEXT_BYTES),
        std::span<uint8_t>(ss, GOAL_MLKEM768_SHARED_SECRET_BYTES), rng);
    return rng.consumed_exactly() ? 0 : 1;
  } catch (...) {
    return 1;
  }
}

extern "C" int goal_mlkem768_decaps(uint8_t *ss, const uint8_t *ct,
                                      const uint8_t *dk) {
  try {
    auto keypair = Botan::Expanded_Keypair_Codec().decode_keypair(
        std::span<const uint8_t>(dk, GOAL_MLKEM768_SECRET_KEY_BYTES),
        mlkem768_constants());
    Botan::ML_KEM_Decryptor operation(keypair.second, keypair.first, "Raw");
    operation.raw_kem_decrypt(
        std::span<uint8_t>(ss, GOAL_MLKEM768_SHARED_SECRET_BYTES),
        std::span<const uint8_t>(ct, GOAL_MLKEM768_CIPHERTEXT_BYTES));
    return 0;
  } catch (...) {
    return 1;
  }
}
