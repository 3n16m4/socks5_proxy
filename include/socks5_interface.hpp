#ifndef SOCKS5_INTERFACE_SOCKS5_INTERFACE_HPP
#define SOCKS5_INTERFACE_SOCKS5_INTERFACE_HPP

#include "socks5.hpp"
#include "socks5_auth.hpp"

#include <sys/socket.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

class socks5_interface final {
public:
  explicit socks5_interface() = default;
  explicit socks5_interface(int socket_fd) : socket_fd_(socket_fd) {}
  explicit socks5_interface(int socket_fd, std::string host, uint16_t port)
      : socket_fd_(socket_fd), host_(std::move(host)), port_(port) {}
  explicit socks5_interface(int socket_fd, std::string username,
                            std::string password, std::string host,
                            uint16_t port)
      : socket_fd_(socket_fd), username_(std::move(username)),
        password_(std::move(password)), host_(std::move(host)), port_(port) {}

  bool sendall(const uint8_t *buffer, std::size_t length) {
    for (std::size_t i = 0; i < length;) {
      ssize_t bytes = send(socket_fd_, &buffer[i], length - i, 0);
      if (bytes < 0) {
        return false;
      }
      i += bytes;
    }
    return true;
  }

  bool recvall(uint8_t *buffer, std::size_t length) {
    size_t total = 0, n = 0;
    while ((n = ::recv(socket_fd_, buffer + total, length - total - 1,
                       MSG_WAITALL)) > 0) {
      total += n;
    }
    buffer[total] = 0;
    return true;
  }

  bool send_method_request(socks5_authentication_method_type auth_type) {
    // 3 bytes
    socks5_method_req_t method_req{};
    method_req.version_ = SOCKS5_VERSION;
    method_req.num_methods_ = 1;
    method_req.methods_[0] = auth_type;

    const auto send_buf = reinterpret_cast<const uint8_t *>(&method_req);
    for (std::size_t i = 0; i < sizeof(method_req); ++i) {
      std::cout << std::hex << (int)send_buf[i] << ' ';
    }
    std::cout << std::endl;
    if (!sendall(send_buf, sizeof(method_req))) {
      return false;
    }

    uint8_t recv_buf[sizeof(socks5_method_reply_t)];
    if (!recvall(recv_buf, sizeof(socks5_method_reply_t))) {
      return false;
    }

    const auto method_reply =
        reinterpret_cast<socks5_method_reply_t *>(&recv_buf);

    std::cout << "method_reply: " << (int)method_reply->version_ << " "
              << (int)method_reply->method_ << '\n';

    if (method_reply->version_ != method_req.version_ or
        method_reply->method_ != method_req.methods_[0]) {
      std::cerr << "method_reply failure!\n";
      return false;
    }
    return true;
  }

  bool authenticate() {
    char *user = nullptr;
    char *pass = nullptr;
    std::strncpy(user, username_.c_str(), username_.size());
    std::strncpy(pass, password_.c_str(), password_.size());

    socks5_user_pass_authentication_req_t user_pass_auth_req{};
    user_pass_auth_req.version_ = AUTH_VERSION;
    user_pass_auth_req.username_length_ = username_.size();
    user_pass_auth_req.username_ = reinterpret_cast<uint8_t *>(user);
    user_pass_auth_req.password_length_ = password_.size();
    user_pass_auth_req.password_ = reinterpret_cast<uint8_t *>(pass);

    const auto send_buf =
        reinterpret_cast<const uint8_t *>(&user_pass_auth_req);
    for (std::size_t i = 0; i < sizeof(user_pass_auth_req); ++i) {
      std::cout << std::hex << (int)send_buf[i] << ' ';
    }
    std::cout << std::endl;
    if (!sendall(send_buf, sizeof(user_pass_auth_req))) {
      return false;
    }

    uint8_t recv_buf[sizeof(socks5_user_pass_authentication_req_t)];
    if (!recvall(recv_buf, sizeof(socks5_user_pass_authentication_req_t))) {
      return false;
    }

    const auto user_pass_auth_reply =
        reinterpret_cast<socks5_user_pass_authentication_reply_t *>(&recv_buf);

    std::cout << "user_pass_auth_reply: " << (int)user_pass_auth_reply->version_
              << " " << (int)user_pass_auth_reply->status_ << '\n';

    if (user_pass_auth_reply->version_ != user_pass_auth_req.version_ or
        user_pass_auth_reply->status_ != user_pass_status_type::success) {
      std::cerr << "user_pass_auth_reply failure!\n";
      return false;
    }
    return true;
  }

  // TODO: finish this
  bool request() { return true; }

private:
  int socket_fd_{};
  std::string username_;
  std::string password_;

  std::string host_;
  uint16_t port_{};
};

#endif // SOCKS5_INTERFACE_SOCKS5_INTERFACE_HPP
