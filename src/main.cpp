#include "mdns.h"

#include <inaddr.h>
#include <string>
#include <vector>
#include <variant>

// Equivalent of mdns_query_t using std::string
struct MdnsQuery {
  mdns_record_type_t type;
  std::string name;
};

// Represents a single result to an mdns query
struct MdnsAResult {
  in_addr addr;
};

struct MdnsAAAAResult {
  in6_addr addr;
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
  std::string key;
  std::string value;
};

struct AdapterInfo {
  std::string name;
  unsigned int index;
};

struct MdnsQueryResult {
  AdapterInfo info;
  mdns_record_type_t type;
  std::string name;  // the record name this result answers for
  uint32_t ttl;
  std::variant<MdnsAResult, MdnsAAAAResult, MdnsPtrResult,
               MdnsSrvResult, MdnsTxtResult> data;
};

class MdnsClient {
public:
  MdnsClient();

  void SendQuery(const std::vector<MdnsQuery> &query);

};

int main(int argc, char **argv) {

}
