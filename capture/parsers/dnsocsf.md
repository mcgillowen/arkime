# DNS OCSF Parser

The idea of this parser is to add features that are missing in the current parser
and to make the output compatible with [OCSF](https://schema.ocsf.io/1.1.0/), specifically the [DNS activity class](https://schema.ocsf.io/1.1.0/classes/dns_activity).

## JSON Representation

```json
{
  "activity_id": 6, // Acceptable values are 0,1,2,6,99
  "category_uid": 4, // Static value for DNS Activity = Network Activity
  "class_uid": 4003, // Static value for DNS Activity = DNS Activity
  "answers": [
    {
      "flag_ids": [4], // Optional DNS answer header flags
      "flags": ["RA"],
      "rdata": "212.10.45.32", // The answer data, depends on type and class, eg. IP
      "packet_uid": 65535, // DNS packet identifier defined in the query
      "class": "IN", // RFC 1035 CLASS value, most likely always `IN`
      "type": "A", // RFC 1035 TYPE value
      "ttl": 0 // The TTL of the response
    }
  ],
  "query": {
    "opcode": "QUERY",
    "opcode_id": 0, // DNS Opcode identifier, values are 0,1,2,3,4,5,6
    "hostname": "www.example.com", // The hostname being queried
    "packet_uid": 65535, // DNS packet identifier defined in the query
    "class": "IN", // RFC 1035 CLASS value, most likely always `IN`
    "type": "A", // RFC 1035 TYPE value
  },
  "dst_endpoint": {
    "ip": "1.1.1.1", // IP of the endpoint, should be the nameserver
    "port": 53, // Port of the endpoint, most likely will be 53
  },
  "time": 1706535741000, // UNIX epoch milliseconds
  "metadata": {
    "product": {
      "vendor_name": "arkime" // Arkime is the data producer
    },
    "version": "1.1.0" // Semver version of the OCSF schema
  },
  "query_time": 1706535741000, // Query time should be the packet timestamp of the query
  "rcode_id": 0, // Response code only if it's a response packet
  "response_time": 1706535741000, // Response time should be the packet timestamp of the response
  "severity_id": 1, // Arkime provides information rather than actions so always, for `Informational`
  "src_endpoint": {
    "ip": "1.1.1.1", // IP of the endpoint, should be the nameserver
    "port": 53, // Port of the endpoint, most likely will be 53
  },
  "type_uid": 400306, // class_uid * 100 + activity_id
}
```
