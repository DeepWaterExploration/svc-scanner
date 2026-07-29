#include "mdns.h"

#include <Winsock2.h>
#include <cstring>
#include <ifdef.h>
#include <inaddr.h>
#include <iostream>
#include <iphlpapi.h>
#include <iptypes.h>
#include <map>
#include <nldef.h>
#include <sstream>
#include <string>
#include <variant>
#include <vector>
#include <wincrypt.h>
#include <winerror.h>
#include <ws2ipdef.h>

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

struct MdnsQueryResult {
  Socket socket;
  int socket_index;
  mdns_record_type_t type;
  std::string name; // the record name this result answers for
  uint32_t ttl;
  MdnsRecordData data;
  std::string from_addr; // TODO: make custom ip class
};

bool IsIpV6LL(sockaddr_in6 *addr) {
  // Link-Local prefix FE80::/10 (1111 1110 10)
  const uint8_t *b = addr->sin6_addr.s6_addr;
  return (b[0] == 0xFE && (b[1] & 0xC0) == 0x80);
}

std::string ip_address_to_string(const struct sockaddr *addr,
                                 unsigned short port, size_t addrlen, unsigned int adapter_index=-1) {
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
    auto ipv6_addr = ((sockaddr_in6*)addr);

    // Check if it's a link-local ip that is missing scope id (seems to happen in the AAAA records)
    if (adapter_index >= 0 && !ipv6_addr->sin6_scope_id && IsIpV6LL(ipv6_addr)) {
      host_ss << "%" << adapter_index;
    }
  }

  if (port != 0) {
    if (addr->sa_family == AF_INET6) {
      str << "[" << host_ss.str() << "]" << ":" << service;
    } else if (addr->sa_family == AF_INET) {
      str << host_ss.str() << ":" << service;
    }
  } else {
    str << host_ss.str();
  }

  return str.str();
}

bool IsLoopback(LPSOCKADDR addr) {
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
    return (saddr->sin_addr.S_un.S_un_b.s_b1 == 127) &&
           (saddr->sin_addr.S_un.S_un_b.s_b2 == 0) &&
           (saddr->sin_addr.S_un.S_un_b.s_b3 == 0) &&
           (saddr->sin_addr.S_un.S_un_b.s_b4 == 1);
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

    std::cout << "Adapter:\n";
    std::wcout << " friendly name: " << adapter->FriendlyName << std::endl;
    std::cout << " addresses: " << std::endl;

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

      std::cout << " - " << addr_str << std::endl;
    }
    std::cout << "\n";
  }
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
  record.socket_index = socket_index;
  record.ttl = ttl;
  record.type = (mdns_record_type_t)rtype;
  record.name = entry_str;
  record.socket = sock;
  record.from_addr = fromaddrstr;

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
    std::string addr_str =
        ip_address_to_string((sockaddr *)&addr, 0, sizeof(addr), sock.adapter.index);

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
          std::cout << "Received " << records
                    << " records for interface: " << sockets_[i].adapter.name
                    << std::endl;
        }
        FD_SET(sockets_[i].isock, &readfs);
      }
    }
  } while (res > 0);
  std::cout << std::endl;
}

int main(int argc, char **argv) {
  WORD versionWanted = MAKEWORD(1, 1);
  WSADATA wsaData;
  if (WSAStartup(versionWanted, &wsaData)) {
    printf("Failed to initialize WinSock\n");
    return -1;
  }
  MdnsClient client;

  client.Open();
  client.SendQuery("_dweos._tcp.local");

  std::vector<MdnsQueryResult> records = client.records();
  for (MdnsQueryResult record : records) {
    std::cout << "From: " << record.from_addr << " ("
              << record.socket.adapter.name << ") - ";
    switch (record.type) {
    case MDNS_RECORDTYPE_PTR:
      std::cout << "PTR: " << std::get<MdnsPtrResult>(record.data).name;
      break;
    case MDNS_RECORDTYPE_SRV:
      std::cout << "SRV: " << std::get<MdnsSrvResult>(record.data).name
                << " at port " << std::get<MdnsSrvResult>(record.data).port
                << " with priority "
                << std::get<MdnsSrvResult>(record.data).priority;
      break;
    case MDNS_RECORDTYPE_A:
      std::cout << "A: " << std::get<MdnsAResult>(record.data).addr;
      break;
    case MDNS_RECORDTYPE_AAAA:
      std::cout << "AAAA: " << std::get<MdnsAAAAResult>(record.data).addr;
      break;
    case MDNS_RECORDTYPE_TXT: {
      MdnsTxtResult result = std::get<MdnsTxtResult>(record.data);
      std::cout << "TXT Records:" << std::endl;
      for (const auto &[key, value] : result.txt_records) {
        std::cout << "\t" << key << ": " << value << std::endl;
      }
      break;
    }
    default:
      break;
    }
    std::cout << std::endl;
  }

  WSACleanup();
}
