/**
 * @file hmac.hpp
 * @brief Minimal HMAC helpers for modern C++ (HMAC-SHA256).
 *
 * Header-only. Designed to pair with the Vix Registry `hashing` library.
 *
 * - HMAC-SHA256: implemented here, using hashing::sha256_bytes(...)
 * - Output: bytes + lowercase hex
 *
 * @author Gaspard Kirira
 *
 * MIT License
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <hashing/hashing.hpp>

namespace hmac
{
  /**
   * @brief Compute HMAC-SHA256 digest bytes.
   *
   * @param key key bytes
   * @param key_size key size
   * @param data message bytes
   * @param data_size message size
   */
  inline std::array<std::uint8_t, 32> hmac_sha256_bytes(
      const std::uint8_t *key,
      std::size_t key_size,
      const std::uint8_t *data,
      std::size_t data_size)
  {
    // SHA-256 block size is 64 bytes
    constexpr std::size_t block_size = 64;

    // Step 1: If key is longer than block size, hash it
    std::array<std::uint8_t, 32> key_hash{};
    bool used_hashed_key = false;

    if (key_size > block_size)
    {
      key_hash = hashing::sha256_bytes(key, key_size);
      used_hashed_key = true;
      key = key_hash.data();
      key_size = key_hash.size();
    }

    // Step 2: Build K0 (block_size bytes)
    std::array<std::uint8_t, block_size> k0{};
    for (std::size_t i = 0; i < block_size; ++i)
      k0[i] = 0;

    for (std::size_t i = 0; i < key_size; ++i)
      k0[i] = key[i];

    (void)used_hashed_key; // keep for readability, no runtime need

    // Step 3: Compute inner = SHA256((K0 xor ipad) || data)
    std::array<std::uint8_t, block_size> inner_pad{};
    for (std::size_t i = 0; i < block_size; ++i)
      inner_pad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x36);

    std::vector<std::uint8_t> inner_msg;
    inner_msg.reserve(block_size + data_size);
    inner_msg.insert(inner_msg.end(), inner_pad.begin(), inner_pad.end());
    inner_msg.insert(inner_msg.end(), data, data + data_size);

    const auto inner_digest = hashing::sha256_bytes(inner_msg.data(), inner_msg.size());

    // Step 4: Compute outer = SHA256((K0 xor opad) || inner_digest)
    std::array<std::uint8_t, block_size> outer_pad{};
    for (std::size_t i = 0; i < block_size; ++i)
      outer_pad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x5c);

    std::vector<std::uint8_t> outer_msg;
    outer_msg.reserve(block_size + inner_digest.size());
    outer_msg.insert(outer_msg.end(), outer_pad.begin(), outer_pad.end());
    outer_msg.insert(outer_msg.end(), inner_digest.begin(), inner_digest.end());

    return hashing::sha256_bytes(outer_msg.data(), outer_msg.size());
  }

  /**
   * @brief Compute HMAC-SHA256 digest bytes (string inputs).
   */
  inline std::array<std::uint8_t, 32> hmac_sha256_bytes(std::string_view key, std::string_view data)
  {
    return hmac_sha256_bytes(
        reinterpret_cast<const std::uint8_t *>(key.data()),
        key.size(),
        reinterpret_cast<const std::uint8_t *>(data.data()),
        data.size());
  }

  /**
   * @brief Compute HMAC-SHA256 as lowercase hex string.
   */
  inline std::string hmac_sha256_hex(std::string_view key, std::string_view data)
  {
    return hashing::to_hex(hmac_sha256_bytes(key, data));
  }

  /**
   * @brief Compute HMAC-SHA256 as lowercase hex string (binary key + binary data).
   */
  inline std::string hmac_sha256_hex(
      const std::uint8_t *key,
      std::size_t key_size,
      const std::uint8_t *data,
      std::size_t data_size)
  {
    return hashing::to_hex(hmac_sha256_bytes(key, key_size, data, data_size));
  }

} // namespace hmac
