#ifndef SVC_SCANNER_HPP
#define SVC_SCANNER_HPP

#include <optional>
#include "mdns_scan.hpp"

namespace dwe {

struct ServiceInstance {
  std::string instance_name;  // e.g. dwesvc-SN90001._dweos._tcp.local.

  std::optional<MdnsSrvResult> srv;
  std::optional<MdnsTxtResult> txt;
};

struct IpRecord {
  MdnsMetaData meta;    // the metadata of the record
  std::string ip_addr;  // the parsed string of the ip record
};

struct HostNode {
  std::string hostname;  // e.g. dwesvc-SN90001.local.

  std::vector<IpRecord> ip_records;

  // map from service instance name to service instance
  std::map<std::string, ServiceInstance> services;
};

inline std::map<std::string, HostNode> ParseHosts(
    const std::vector<MdnsQueryResult>& records) {
  // map from hostname to its services
  std::map<std::string, HostNode> hosts;
  // map from instance name to hostname
  std::map<std::string, std::string> instance_to_host;

  // Iterate only over the hostname records
  // Depending on the type of record, the entry name has a different meaning
  // A, and AAAA records, the entry name is the hostname of the device
  // On SRV records, the entry name is the service name, which SRV points to
  // the hostname
  for (const auto& record : records) {
    if (record.meta.type == MDNS_RECORDTYPE_SRV) {
      const auto& srv = std::get<MdnsSrvResult>(record.data);
      HostNode& host = hosts[srv.name];
      host.hostname = srv.name;

      // record.name = instance for SRV records
      auto& service = host.services[record.meta.name];
      service.instance_name = record.meta.name;
      service.srv = srv;
      instance_to_host[record.meta.name] = srv.name;
    } else if (record.meta.type == MDNS_RECORDTYPE_A) {
      const auto& a_record = std::get<MdnsAResult>(record.data);
      IpRecord ip_record;
      ip_record.ip_addr = a_record.addr;
      ip_record.meta = record.meta;
      hosts[record.meta.name].ip_records.push_back(ip_record);
    } else if (record.meta.type == MDNS_RECORDTYPE_AAAA) {
      const auto& aaaa_record = std::get<MdnsAAAAResult>(record.data);
      IpRecord ip_record;
      ip_record.ip_addr = aaaa_record.addr;
      ip_record.meta = record.meta;
      hosts[record.meta.name].ip_records.push_back(ip_record);
    }
  }

  // TXT records have an entry name that is the service name (from SRV)
  // Thus we can point from TXT -> SRV -> Host and have a full correlation
  // This is not optimal, we can create a list of orphaned TXT records, but
  // this is a relatively minimal approach that's easy to debug and extend.
  for (const auto& record : records) {
    // We intentionally ignore PTR records, since they aren't useful
    if (record.meta.type == MDNS_RECORDTYPE_TXT) {
      const auto& txt_record = std::get<MdnsTxtResult>(record.data);

      if (instance_to_host.find(record.meta.name) != instance_to_host.end()) {
        std::string hostname = instance_to_host[record.meta.name];
        hosts[hostname].services[record.meta.name].txt = txt_record;
      } else {
        // Extremely rare case that the data was lost. This should indicate a
        // rescan is required
        std::cout << "Orphaned TXT record - " << record.meta.name << std::endl;
      }
    }
  }

  return hosts;
}
}  // namespace dwe

#endif
