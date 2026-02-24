#include <hmac/hmac.hpp>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

static std::vector<std::uint8_t> make_binary_key()
{
  // Example: binary key with zeros and high bytes (common in token/signing systems)
  return {0x00, 0x01, 0xff, 0x10, 0x42, 0x00, 0x7e, 0x80};
}

int main()
{
  const auto key = make_binary_key();
  const std::string msg = "payload";

  const std::string mac = hmac::hmac_sha256_hex(
      key.data(), key.size(),
      reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size());

  std::cout << "msg  : " << msg << "\n";
  std::cout << "hmac : " << mac << "\n";
  return 0;
}
