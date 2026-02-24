#include <hmac/hmac.hpp>

#include <iostream>
#include <string>

int main()
{
  const auto mac = hmac::hmac_sha256_bytes("secret", "abc");
  const std::string hex = hashing::to_hex(mac);

  std::cout << "hmac_sha256_bytes(\"secret\",\"abc\") = " << hex << "\n";
  return 0;
}
