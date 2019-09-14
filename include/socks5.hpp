#ifndef SOCKS5_INTERFACE_SOCKS5_HPP
#define SOCKS5_INTERFACE_SOCKS5_HPP

/**
 * Only supports ipv4, tcp for now.
 * Reference: https://tools.ietf.org/html/rfc1928
 */

constexpr uint8_t MAX_METHODS = 255;
constexpr uint8_t SOCKS5_VERSION = 0x05;

enum class socks5_authentication_method_type : uint8_t {
  no_authentication_required = 0x00,
  gssapi = 0x01,
  username_password = 0x02,
  iana_assigned = 0x03,    // 0x03 - 0x7f
  reserved_private = 0x80, // 0x80 - 0xfe
  no_acceptable_methods = 0xff
};
enum class socks5_command_type : uint8_t { connect, bind, udp_associate };
enum class socks5_address_type : uint8_t {
  ipv4 = 0x01,
  domain_name = 0x03,
  ipv6 = 0x04
};
enum class socks5_reply_type : uint8_t {
  succeeded,                  // X'00' succeeded
  server_failure,             // X'01' general SOCKS server failure
  connection_not_allowed,     // X'02' connection not allowed by ruleset
  network_unreachable,        // X'03' Network unreachable
  host_unreachable,           // X'04' Host unreachable
  connection_refused,         // X'05' Connection refused
  ttl_expired,                // X'06' TTL expired
  command_not_supported,      // X'07' Command not supported
  address_type_not_supported, // X'08' Address type not supported
  unassigned                  // X'09' to X'FF' unassigned
};

typedef struct ipv4 {
  uint32_t address_;
} ipv4_t;

typedef struct ipv6 {
  uint8_t address_[16];
} ipv6_t;

// fully qualified domain name
typedef struct fqdn {
  uint8_t octet_[4];
} fqdn_t;

typedef struct dst_address {
  ipv4_t ipv4_;
  ipv6_t ipv6_;
  fqdn_t fqdn_;
} dst_address_t;

// yes, i know this is a redeclaration. however, typedef redefinitions are ugly.
typedef struct bnd_address {
  ipv4_t ipv4_;
  ipv6_t ipv6_;
  fqdn_t fqdn_;
} bnd_address_t;

typedef struct socks5_method_req {
  uint8_t version_;
  uint8_t num_methods_;
  socks5_authentication_method_type methods_[1];
} socks5_method_req_t;

typedef struct socks5_method_reply {
  uint8_t version_;
  socks5_authentication_method_type method_;
} socks5_method_reply_t;

typedef struct socks5_request {
  uint8_t version_; // must be 0x05
  socks5_command_type command_;
  uint8_t reserved_; // must be 0x00
  socks5_address_type address_type_;
  dst_address_t dst_address_;
  uint16_t port_;
} socks5_request_t;

typedef struct socks5_reply {
  uint8_t version_; // must be 0x05
  socks5_reply_type reply_;
  uint8_t reserved_; // must be 0x00
  socks5_address_type address_type_;
  bnd_address_t bnd_address_;
  uint16_t port_;
} socks5_reply_t;

#endif // SOCKS5_INTERFACE_SOCKS5_HPP
