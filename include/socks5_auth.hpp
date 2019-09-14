#ifndef SOCKS5_INTERFACE_SOCKS5_AUTH_HPP
#define SOCKS5_INTERFACE_SOCKS5_AUTH_HPP

#include <cstdint>

/**
 * Only supports username/password authentication for now.
 * Reference: https://tools.ietf.org/html/rfc1929
 */

constexpr uint8_t AUTH_VERSION = 0x01;

enum class user_pass_status_type {
  success, // 0x00
  failure  // anything other than 0x00
};

typedef struct socks5_user_pass_authentication_req {
  uint8_t version_; // must be 0x01 for current user/pass authentication
  uint8_t username_length_;
  uint8_t *username_; // 1 to 255
  uint8_t password_length_;
  uint8_t *password_; // 1 to 255
} socks5_user_pass_authentication_req_t;

typedef struct socks5_user_pass_authentication_reply {
  uint8_t version_; // must be 0x01 for current user/pass authentication
  user_pass_status_type status_;
} socks5_user_pass_authentication_reply_t;

#endif // SOCKS5_INTERFACE_SOCKS5_AUTH_HPP
