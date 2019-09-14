#include <iostream>

#include "../include/socks5_proxy.hpp"

int main() {
  using namespace andromeda;

  const std::string proxy_host = "188.226.141.127";
  const uint16_t proxy_port = 1080;
  const std::string host = "google.com";
  const uint16_t port = 80;
  // optional
  const std::string username = "someuser";
  const std::string password = "somepassword";

  socks5_proxy proxy{proxy_host, proxy_port, host, port};
  if (!proxy.connect()) {
    return 1;
  }
  return 0;
}