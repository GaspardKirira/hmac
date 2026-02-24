# hmac

Minimal HMAC utilities for modern C++.

`hmac` provides a clean and lightweight implementation of HMAC-SHA256,
built on top of the `hashing` library.

Header-only. No heavy dependencies.

## Download

https://vixcpp.com/registry/pkg/gaspardkirira/hmac

## Why hmac?

Unlike large cryptography frameworks, this library:

-   Implements HMAC-SHA256
-   Supports hex and raw byte output
-   Works with string or binary keys
-   Is fully header-only
-   Has zero required dependencies beyond `hashing`
-   Is easy to integrate into small tools and services

Perfect for:

-   API request signing
-   JWT-style token generation
-   Webhook verification
-   Message authentication
-   CLI tools
-   Secure build pipelines

## Installation

### Using Vix Registry

``` bash
vix add gaspardkirira/hmac
vix deps
```

This will automatically install:

-   `gaspardkirira/hashing`

### Manual

Clone the repository:

``` bash
git clone https://github.com/GaspardKirira/hmac.git
```

Add the `include/` directory to your project and make sure `hashing` is
also available.

## Quick Example

``` cpp
#include <hmac/hmac.hpp>
#include <iostream>

int main()
{
  std::string key = "secret";
  std::string message = "hello world";

  std::string mac = hmac::hmac_sha256_hex(key, message);

  std::cout << "HMAC: " << mac << "\n";
}
```

## Binary Key Example

``` cpp
#include <hmac/hmac.hpp>
#include <vector>
#include <iostream>

int main()
{
  std::vector<std::uint8_t> key = {0x00, 0x01, 0xff, 0x42};
  std::string message = "payload";

  std::string mac = hmac::hmac_sha256_hex(
    key.data(), key.size(),
    reinterpret_cast<const std::uint8_t*>(message.data()),
    message.size()
  );

  std::cout << mac << "\n";
}
```

## API Overview

``` cpp
hmac::hmac_sha256_bytes(key_ptr, key_size, data_ptr, data_size);
hmac::hmac_sha256_bytes("key", "data");

hmac::hmac_sha256_hex("key", "data");

hmac::hmac_sha256_hex(key_ptr, key_size, data_ptr, data_size);
```

Returns:

-   `std::array<uint8_t, 32>` for raw bytes
-   `std::string` for lowercase hex output

## Cryptographic Notes

-   Uses SHA-256 internally via the `hashing` library
-   Block size: 64 bytes (SHA-256 standard)
-   Output size: 32 bytes
-   Fully deterministic
-   No hidden global state

This library intentionally focuses on HMAC-SHA256 only. It does not aim
to replace full cryptographic toolkits.

## Tests

Run:

``` bash
vix build
vix tests
```

Test vectors include official RFC 4231 HMAC-SHA256 cases.

## Design Philosophy

`hmac` focuses on:

-   Minimal surface area
-   Clear and explicit APIs
-   Zero configuration
-   Deterministic behavior
-   Small integration footprint

Built for modern C++ systems where simplicity matters.

## License

MIT License
Copyright (c) Gaspard Kirira

