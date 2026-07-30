#include <optional>
#include <vector>
#include "mdns.h"
#include "mdns_scan.hpp"
#include "svc_scanner.hpp"

using namespace dwe;

int main(int argc, char** argv) {
#ifdef _WIN32
  WORD versionWanted = MAKEWORD(1, 1);
  WSADATA wsaData;
  if (WSAStartup(versionWanted, &wsaData)) {
    printf("Failed to initialize WinSock\n");
    return -1;
  }
#endif
  MdnsClient client;

  client.Open();
  client.SendQuery("_dwesdk._tcp.local");

  auto hosts = ParseHosts(client.records());

  for (const auto& [hostname, host] : hosts) {
    std::cout << "HOST: " << hostname << "\n";

    std::cout << "  IP Addresses:\n";
    for (const auto& a : host.ip_records) {
      std::cout << "    - " << a.ip_addr << " (" << a.meta.adapter.name << ")"
                << "\n";
    }

    std::cout << "  Services:\n";
    for (const auto& [inst_name, svc] : host.services) {
      std::cout << "    - " << inst_name << "\n";
      if (svc.srv) {
        std::cout << "        Port: " << svc.srv->port << "\n";
      }
      if (svc.txt) {
        for (const auto& [k, v] : svc.txt->txt_records) {
          std::cout << "        TXT: " << k << " = " << v << "\n";
        }
      }
    }
    std::cout << "\n";
  }

#ifdef _WIN32
  WSACleanup();
#endif
}
