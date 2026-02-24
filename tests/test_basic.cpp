#include <hmac/hmac.hpp>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

static void expect_eq(const std::string &got, const std::string &want, const char *msg)
{
  if (got != want)
  {
    std::cerr << "FAIL: " << msg << "\n"
              << "  got : " << got << "\n"
              << "  want: " << want << "\n";
    std::exit(1);
  }
}

static std::vector<std::uint8_t> repeat_byte(std::uint8_t b, std::size_t n)
{
  return std::vector<std::uint8_t>(n, b);
}

int main()
{
  // RFC 4231 test vectors for HMAC-SHA-256

  // Test Case 1
  // key = 0x0b repeated 20 times
  // data = "Hi There"
  {
    const auto key = repeat_byte(0x0b, 20);
    const std::string data = "Hi There";

    const std::string got = hmac::hmac_sha256_hex(
        key.data(), key.size(),
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size());

    const std::string want =
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7";

    expect_eq(got, want, "rfc4231 tc1");
  }

  // Test Case 2
  // key = "Jefe"
  // data = "what do ya want for nothing?"
  {
    const std::string key = "Jefe";
    const std::string data = "what do ya want for nothing?";

    const std::string got = hmac::hmac_sha256_hex(key, data);

    const std::string want =
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843";

    expect_eq(got, want, "rfc4231 tc2");
  }

  // Test Case 3
  // key = 0xaa repeated 20 times
  // data = 0xdd repeated 50 times
  {
    const auto key = repeat_byte(0xaa, 20);
    const auto data = repeat_byte(0xdd, 50);

    const std::string got = hmac::hmac_sha256_hex(
        key.data(), key.size(),
        data.data(), data.size());

    const std::string want =
        "773ea91e36800e46854db8ebd09181a7"
        "2959098b3ef8c122d9635514ced565fe";

    expect_eq(got, want, "rfc4231 tc3");
  }

  std::cout << "ok\n";
  return 0;
}
