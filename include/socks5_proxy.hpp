#ifndef SOCKS5_INTERFACE_SOCKS5_PROXY_HPP
#define SOCKS5_INTERFACE_SOCKS5_PROXY_HPP

#include "socks5_interface.hpp"

#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * represents a socks5_proxy.
 * -----------------------------------------------------------------------------
 * host, port represent the specified proxy's host and port.
 * the socket_fd in this class shall be used for further communication with
 * the actual destination host and port.
 * all incoming / outcoming packets will be redirected to the proxy host
 * instead.
 */
namespace andromeda {
class socks5_proxy final {
public:
  using socks5_interface_type = std::unique_ptr<socks5_interface>;

  explicit socks5_proxy() = default;
  explicit socks5_proxy(std::string proxy_host, uint16_t proxy_port,
                        std::string host, uint16_t port)
      : proxy_host_(std::move(proxy_host)), proxy_port_(proxy_port),
        host_(std::move(host)), port_(port), authentication_(false) {}

  explicit socks5_proxy(std::string proxy_host, uint16_t proxy_port,
                        std::string host, uint16_t port, std::string username,
                        std::string password)
      : proxy_host_(std::move(proxy_host)), proxy_port_(proxy_port),
        host_(std::move(host)), port_(port), username_(std::move(username)),
        password_(std::move(password)), authentication_(true) {}
  ~socks5_proxy() = default;

  // connects to a specified proxy host and port.
  // a user/password authentication can be specified in the parameter.
  bool connect() { return connect(proxy_host_, proxy_port_); }
  bool connect(const std::string &proxy_host, uint16_t proxy_port) {
    std::memset(&socket_addr_, 0, sizeof(sockaddr_in));
    socket_addr_.sin_family = AF_INET;
    socket_addr_.sin_addr.s_addr = inet_addr(proxy_host.c_str());
    socket_addr_.sin_port = htons(proxy_port);

    socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ == -1) {
      return false;
    }

    std::cout << "Connecting to " << proxy_host << ':' << proxy_port << '\n';
    if (::connect(socket_fd_,
                  reinterpret_cast<struct sockaddr *>(&socket_addr_),
                  sizeof(sockaddr_in)) == -1) {
      std::cerr << "Connection error: " << errno << '\n';
      close(socket_fd_);
      return false;
    }
    std::cout << "Connected to " << proxy_host << ':' << proxy_port << '\n';

    if (authentication_) {
      socks5_interface_ = std::make_unique<socks5_interface>(
          socket_fd_, username_, password_, host_, port_);
      if (!socks5_interface_->send_method_request(
              socks5_authentication_method_type::username_password)) {
        // method request failed!
        return false;
      }
      if (!socks5_interface_->authenticate()) {
        // authentication failed!
        return false;
      }
    } else {
      socks5_interface_ =
          std::make_unique<socks5_interface>(socket_fd_, host_, port_);
      if (!socks5_interface_->send_method_request(
              socks5_authentication_method_type::no_authentication_required)) {
        // method request failed!
        return false;
      }
    }
    return true;
  }

private:
  // proxy ip:port
  std::string proxy_host_;
  uint16_t proxy_port_{};

  // dst address
  std::string host_;
  uint16_t port_{};

  // username, password for proxy
  std::string username_;
  std::string password_;

  bool authentication_{};

  int socket_fd_{};
  struct sockaddr_in socket_addr_ {};

  socks5_interface_type socks5_interface_;
};
} // namespace andromeda

#endif // SOCKS5_INTERFACE_SOCKS5_PROXY_HPP
