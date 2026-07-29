#include "mdns.h"
#include <sys/socket.h>

#ifdef __WIN32
#include <Winsock2.h>
#include <ifdef.h>
#include <inaddr.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <nldef.h>
#include <wincrypt.h>
#include <winerror.h>
#include <ws2ipdef.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/time.h>
#endif

#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

// Equivalent of mdns_query_t using std::string
struct MdnsQuery {
  mdns_record_type_t type;
  std::string name;
};

// Represents a single result to an mdns query
struct MdnsAResult {
  std::string addr;
};

struct MdnsAAAAResult {
  std::string addr;
};

struct MdnsPtrResult {
  std::string name;
};

struct MdnsSrvResult {
  std::string name;
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
};

struct MdnsTxtResult {
  std::map<std::string, std::string> txt_records;
};

struct AdapterInfo {
  std::string name;
  unsigned int index;
};

struct Socket {
  int isock;
  AdapterInfo adapter;
};

using MdnsRecordData = std::variant<MdnsAResult, MdnsAAAAResult, MdnsPtrResult,
                                    MdnsSrvResult, MdnsTxtResult>;

struct MdnsMetaData {
  AdapterInfo adapter;
  mdns_record_type_t type;
  std::string name; // the record name this result answers for
  uint32_t ttl;
  std::string from_addr; // TODO: make custom ip class
};

struct MdnsQueryResult {
  MdnsMetaData meta;
  MdnsRecordData data;
};

bool IsIpV6LL(sockaddr_in6 *addr) {
  // Link-Local prefix FE80::/10 (1111 1110 10)
  const uint8_t *b = addr->sin6_addr.s6_addr;
  return (b[0] == 0xFE && (b[1] & 0xC0) == 0x80);
}

std::string ip_address_to_string(const struct sockaddr *addr,
                                 unsigned short port, size_t addrlen,
                                 unsigned int adapter_index = -1) {
  std::stringstream str;

  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  int ret = getnameinfo(addr, (socklen_t)addrlen, host, NI_MAXHOST, service,
                        NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

  if (ret != 0) {
    std::cout << "Failed!\n";
    return "";
  }

  std::stringstream host_ss;
  host_ss << host;

  if (addr->sa_family == AF_INET6) {
    auto ipv6_addr = ((sockaddr_in6 *)addr);

    // Check if it's a link-local ip that is missing scope id (seems to happen
    // in the AAAA records)
    if (adapter_index >= 0 && !ipv6_addr->sin6_scope_id &&
        IsIpV6LL(ipv6_addr)) {
      host_ss << "%" << adapter_index;
    }
  }

  if (port != 0) {
    if (addr->sa_family == AF_INET6) {
      str << "[" << host_ss.str() << "]"
          << ":" << service;
    } else if (addr->sa_family == AF_INET) {
      str << host_ss.str() << ":" << service;
    }
  } else {
    str << host_ss.str();
  }

  return str.str();
}

bool IsLoopback(const struct sockaddr *addr) {
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
#ifdef _WIN32
    return (saddr->sin_addr.S_un.S_un_b.s_b1 == 127) &&
           (saddr->sin_addr.S_un.S_un_b.s_b2 == 0) &&
           (saddr->sin_addr.S_un.S_un_b.s_b3 == 0) &&
           (saddr->sin_addr.S_un.S_un_b.s_b4 == 1);
#else
    return saddr->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
#endif
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)addr;
    static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 1};
    static const unsigned char localhost_mapped[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};

    return !memcmp(saddr->sin6_addr.s6_addr, localhost, 16) ||
           !memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16);
  }
  return false;
}

#ifndef _WIN32
static bool IsBridgeInterface(const std::string &name) {
  std::string path = "/sys/class/net/" + name + "/bridge";
  struct stat st;
  return stat(path.c_str(), &st) == 0;
}
#endif

std::string ToString(mdns_string_t str) {
  // copy into string
  return std::string(str.str, str.length);
}

class MdnsClient {
public:
  MdnsClient();

  void Open();

  void Close();

  ~MdnsClient();

  void SendQuery(std::string service);

  std::vector<MdnsQueryResult> records() const;

  struct QueryResponseContext {
    MdnsClient *client;
    int socket_index;
  };

private:
  std::vector<Socket> sockets_;

  std::vector<MdnsQueryResult> records_;

  bool is_open_;

  void OpenSockets_();

  int QueryCallback_(const struct sockaddr *from, size_t addrlen,
                     mdns_entry_type_t entry, uint16_t rtype, uint16_t rclass,
                     uint32_t ttl, const void *data, size_t size,
                     size_t name_offset, size_t record_offset,
                     size_t record_length, uint16_t socket_index);
};

MdnsClient::MdnsClient() : is_open_(false) {}

void MdnsClient::Open() {
  if (is_open_)
    Close();

  is_open_ = true;
  OpenSockets_();
}

void MdnsClient::Close() {
  if (!is_open_)
    return;

  for (Socket socket : sockets_) {
    mdns_socket_close(socket.isock);
  }
  sockets_.clear();
}

MdnsClient::~MdnsClient() {
  if (is_open_) {
    Close();
  }
}

std::vector<MdnsQueryResult> MdnsClient::records() const { return records_; }

void MdnsClient::OpenSockets_() {
#ifdef _WIN32
  IP_ADAPTER_ADDRESSES *adapter_address = 0;

  ULONG address_size = 15000;
  unsigned int ret;
  unsigned int num_retries = 3;

  do {
    adapter_address = (IP_ADAPTER_ADDRESSES *)malloc(address_size);
    ret = GetAdaptersAddresses(AF_UNSPEC,
                               GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST,
                               0, adapter_address, &address_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      free(adapter_address);
      // sample mdns.c doubles address size here, but Windows does not
    } else {
      break;
    }
  } while (ret == ERROR_BUFFER_OVERFLOW && num_retries-- > 0);

  if (ret != NO_ERROR || !adapter_address) {
    std::cerr << "Failed to execute GetAdaptersAddresses!";
    return;
  }

  for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter;
       adapter = adapter->Next) {
    if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
      continue;
    if (adapter->OperStatus != IfOperStatusUp)
      continue;

    // std::cout << "Adapter:\n";
    // std::wcout << " friendly name: " << adapter->FriendlyName << std::endl;
    // std::cout << " addresses: " << std::endl;

    for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
         unicast; unicast = unicast->Next) {
      if (IsLoopback(unicast->Address.lpSockaddr))
        continue;

      std::string addr_str = "";

      if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
        struct sockaddr_in *saddr =
            (struct sockaddr_in *)unicast->Address.lpSockaddr;

        int sock = mdns_socket_open_ipv4(saddr);

        AdapterInfo info;
        info.index = adapter->IfIndex;
        std::wstring ws(adapter->FriendlyName);
        info.name = std::string(ws.begin(), ws.end());

        if (sock >= 0) {
          Socket socket_info;
          socket_info.isock = sock;
          socket_info.adapter = info;
          sockets_.push_back(socket_info);
        }

        addr_str = ip_address_to_string(unicast->Address.lpSockaddr,
                                        saddr->sin_port, sizeof(sockaddr_in));
      } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
        if (unicast->DadState != NldsPreferred)
          continue;

        struct sockaddr_in6 *saddr =
            (struct sockaddr_in6 *)unicast->Address.lpSockaddr;

        saddr->sin6_port = 0;
        int sock = mdns_socket_open_ipv6(saddr);

        AdapterInfo info;
        info.index = adapter->Ipv6IfIndex;
        std::wstring ws(adapter->FriendlyName);
        info.name = std::string(ws.begin(), ws.end());

        if (sock >= 0) {
          Socket socket_info;
          socket_info.isock = sock;
          socket_info.adapter = info;
          sockets_.push_back(socket_info);
        }

        addr_str = ip_address_to_string(unicast->Address.lpSockaddr,
                                        saddr->sin6_port, sizeof(sockaddr_in6));
      }

      // std::cout << " - " << addr_str << std::endl;
    }
    // std::cout << "\n";
  }
#else
  struct ifaddrs *ifaddr = 0;
  struct ifaddrs *ifa = 0;

  if (getifaddrs(&ifaddr) < 0) {
    std::cerr << "Failed to get interface addresses!" << std::endl;
    return;
  }

  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr)
      continue;
    if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
      continue;
    if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
      continue;

    if (IsLoopback(ifa->ifa_addr) || IsBridgeInterface(ifa->ifa_name))
      continue;

    std::string addr_str = "";

    AdapterInfo info;
    info.index = if_nametoindex(ifa->ifa_name);
    info.name = ifa->ifa_name;

    if (ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;
      saddr->sin_port = 0;
      int sock = mdns_socket_open_ipv4(saddr);

      if (sock >= 0) {
        Socket socket_info;
        socket_info.isock = sock;
        socket_info.adapter = info;
        sockets_.push_back(socket_info);
      }

      addr_str = ip_address_to_string(ifa->ifa_addr, saddr->sin_port,
                                      sizeof(sockaddr_in));
    } else if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)ifa->ifa_addr;
      saddr->sin6_port = 0;
      int sock = mdns_socket_open_ipv6(saddr);

      if (sock >= 0) {
        Socket socket_info;
        socket_info.isock = sock;
        socket_info.adapter = info;
        sockets_.push_back(socket_info);
      }

      addr_str = ip_address_to_string(ifa->ifa_addr, saddr->sin6_port,
                                      sizeof(sockaddr_in6));
    } else {
      continue; // ignore AF_PACKET
    }

    std::cout << "Adapter:\n";
    std::wcout << " friendly name: " << ifa->ifa_name << std::endl;
    std::cout << " - " << addr_str << std::endl;
  }
  std::cout << "\n";

#endif
}

int MdnsClient::QueryCallback_(const struct sockaddr *from, size_t addrlen,
                               mdns_entry_type_t entry, uint16_t rtype,
                               uint16_t rclass, uint32_t ttl, const void *data,
                               size_t size, size_t name_offset,
                               size_t record_offset, size_t record_length,
                               uint16_t socket_index) {
  std::string fromaddrstr = ip_address_to_string(from, 0, addrlen);
  char namebuffer[256];
  char entrybuffer[256];
  static mdns_record_txt_t txtbuffer[128];

  std::string entry_str = ToString(mdns_string_extract(
      data, size, &name_offset, entrybuffer, sizeof(entrybuffer)));

  Socket sock = sockets_[socket_index];

  MdnsQueryResult record;
  record.meta.ttl = ttl;
  record.meta.type = (mdns_record_type_t)rtype;
  record.meta.name = entry_str;
  record.meta.adapter = sock.adapter;
  record.meta.from_addr = fromaddrstr;

  int scope_id = 0;
  if (from->sa_family == AF_INET6) {
    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)from;
    scope_id = saddr->sin6_scope_id;
  }

  MdnsRecordData record_data;

  if (rtype == MDNS_RECORDTYPE_PTR) {
    std::string name_str =
        ToString(mdns_record_parse_ptr(data, size, record_offset, record_length,
                                       namebuffer, sizeof(namebuffer)));

    MdnsPtrResult result;
    result.name = name_str;
    record.data = result;
    record_data = result;
  } else if (rtype == MDNS_RECORDTYPE_SRV) {
    mdns_record_srv_t srv =
        mdns_record_parse_srv(data, size, record_offset, record_length,
                              namebuffer, sizeof(namebuffer));
    MdnsSrvResult result;
    result.name = ToString(srv.name);
    result.port = srv.port;
    result.priority = srv.priority;
    result.weight = srv.weight;
    record_data = result;
  } else if (rtype == MDNS_RECORDTYPE_A) {
    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    std::string addr_str =
        ip_address_to_string((sockaddr *)&addr, 0, sizeof(addr));

    MdnsAResult result;
    result.addr = addr_str;
    record_data = result;
  } else if (rtype == MDNS_RECORDTYPE_AAAA) {
    struct sockaddr_in6 addr;
    mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
    // Include the adapter index for the case of ipv6ll
    std::string addr_str = ip_address_to_string(
        (sockaddr *)&addr, 0, sizeof(addr), sock.adapter.index);

    MdnsAAAAResult result;
    result.addr = addr_str;
    record_data = result;
  } else if (rtype == MDNS_RECORDTYPE_TXT) {
    MdnsTxtResult result;
    size_t parsed = mdns_record_parse_txt(
        data, size, record_offset, record_length, txtbuffer,
        sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
    for (size_t itxt = 0; itxt < parsed; ++itxt) {
      std::string key = ToString(txtbuffer[itxt].key);
      std::string value =
          txtbuffer[itxt].value.length ? ToString(txtbuffer[itxt].value) : "";
      result.txt_records[key] = value;
    }
    record_data = result;
  } else {
    return 0;
  }

  record.data = record_data;
  records_.push_back(record);

  return 0;
}

void MdnsClient::SendQuery(std::string service) {
  if (!is_open_)
    return;

  std::vector<int> query_ids = {};
  query_ids.resize(sockets_.size());

  std::vector<uint8_t> buffer(2048);

  int nfds = 0;
  size_t total_records = 0;

  for (int i = 0; i < sockets_.size(); i++) {
    Socket socket = sockets_[i];
    query_ids[i] = mdns_query_send(socket.isock, MDNS_RECORDTYPE_PTR,
                                   service.data(), strlen(service.data()),
                                   buffer.data(), buffer.size(), 0);

    if (query_ids[i] < 0) {
      std::cout << "Failed to send mDNS query: " << strerror(errno) << "\n";
    }
  }

  int res = 0;

  do {
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    fd_set readfs;
    FD_ZERO(&readfs);
    int nfds = 0;
    for (Socket socket : sockets_) {
      if (socket.isock >= nfds)
        nfds = socket.isock + 1;
      FD_SET(socket.isock, &readfs);
    }

    total_records = 0;
    res = select(nfds, &readfs, 0, 0, &timeout);
    if (res > 0) {
      for (int i = 0; i < sockets_.size(); i++) {
        if (FD_ISSET(sockets_[i].isock, &readfs)) {
          QueryResponseContext ctx;
          ctx.client = this;
          ctx.socket_index = i;

          int records = mdns_query_recv(
              sockets_[i].isock, buffer.data(), buffer.size(),
              [](int sock, const struct sockaddr *from, size_t addrlen,
                 mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
                 uint16_t rclass, uint32_t ttl, const void *data, size_t size,
                 size_t name_offset, size_t name_length, size_t record_offset,
                 size_t record_length, void *user_data) -> int {
                QueryResponseContext *ctx =
                    static_cast<QueryResponseContext *>(user_data);
                ctx->client->QueryCallback_(from, addrlen, entry, rtype, rclass,
                                            ttl, data, size, name_offset,
                                            record_offset, record_length,
                                            ctx->socket_index);
                return 0;
              },
              (void *)&ctx, query_ids[i]);
          total_records += records;
          // std::cout << "Received " << records
          //           << " records for interface: " << sockets_[i].adapter.name
          //           << std::endl;
        }
        FD_SET(sockets_[i].isock, &readfs);
      }
    }
  } while (res > 0);
  // std::cout << std::endl;
}
