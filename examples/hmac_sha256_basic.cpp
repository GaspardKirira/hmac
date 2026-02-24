#include <hmac/hmac.hpp>

#include <iostream>
#include <string>

int main()
{
  const std::string key = "secret";
  const std::string msg = "hello world";

  const std::string mac = hmac::hmac_sha256_hex(key, msg);

  std::cout << "key  : " << key << "\n";
  std::cout << "msg  : " << msg << "\n";
  std::cout << "hmac : " << mac << "\n";
  return 0;
}
