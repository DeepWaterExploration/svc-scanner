#include "mdns.h"
#include "mdns_scan.hpp"
#include <optional>
#include <vector>

struct ServiceInstance {
  std::string instance_name; // e.g. dwesvc-SN90001._dweos._tcp.local.

  std::optional<MdnsSrvResult> srv;
  std::optional<MdnsTxtResult> txt;
};

struct IpRecord {
  MdnsMetaData meta;
  std::string ip_addr;
};

struct HostNode {
  std::string hostname; // e.g. dwesvc-SN90001.local.

  std::vector<IpRecord> ip_records;

  // map from service instance name to service instance
  std::map<std::string, ServiceInstance> services;
};

int main(int argc, char **argv) {
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

  // map from hostname to its services
  std::map<std::string, HostNode> hosts;
  // map from instance name to hostname
  std::map<std::string, std::string> instance_to_host;

  std::vector<MdnsQueryResult> records = client.records();

  // Iterate only over the hostname records
  for (MdnsQueryResult record : records) {
    if (record.meta.type == MDNS_RECORDTYPE_SRV) {
      const auto &srv = std::get<MdnsSrvResult>(record.data);
      HostNode &host = hosts[srv.name];
      host.hostname = srv.name;

      // record.name = instance for SRV records
      auto &service = host.services[record.meta.name];
      service.instance_name = record.meta.name;
      service.srv = srv;
      instance_to_host[record.meta.name] = srv.name;
    } else if (record.meta.type == MDNS_RECORDTYPE_A) {
      const auto &a_record = std::get<MdnsAResult>(record.data);
      IpRecord ip_record;
      ip_record.ip_addr = a_record.addr;
      ip_record.meta = record.meta;
      hosts[record.meta.name].ip_records.push_back(ip_record);
    } else if (record.meta.type == MDNS_RECORDTYPE_AAAA) {
      const auto &aaaa_record = std::get<MdnsAAAAResult>(record.data);
      IpRecord ip_record;
      ip_record.ip_addr = aaaa_record.addr;
      ip_record.meta = record.meta;
      hosts[record.meta.name].ip_records.push_back(ip_record);
    }
  }

  for (MdnsQueryResult record : records) {
    // We intentionally ignore PTR records, since they aren't useful
    if (record.meta.type == MDNS_RECORDTYPE_TXT) {
      const auto &txt_record = std::get<MdnsTxtResult>(record.data);

      if (instance_to_host.find(record.meta.name) != instance_to_host.end()) {
        std::string hostname = instance_to_host[record.meta.name];
        hosts[hostname].services[record.meta.name].txt = txt_record;
      } else {
        std::cout << "Orphaned TXT record - " << record.meta.name << std::endl;
      }
    }
  }

  for (const auto &[hostname, host] : hosts) {
    std::cout << "HOST: " << hostname << "\n";

    std::cout << "  IP Addresses:\n";
    for (const auto &a : host.ip_records) {
      std::cout << "    - " << a.ip_addr << " (" << a.meta.adapter.name << ")"
                << "\n";
    }

    std::cout << "  Services:\n";
    for (const auto &[inst_name, svc] : host.services) {
      std::cout << "    - " << inst_name << "\n";
      if (svc.srv) {
        std::cout << "        Port: " << svc.srv->port << "\n";
      }
      if (svc.txt) {
        for (const auto &[k, v] : svc.txt->txt_records) {
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
