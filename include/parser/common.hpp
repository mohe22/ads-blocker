#pragma once

#include <cstdint>
#include <string>
#include <winsock2.h> // for host to network conversion


namespace DNS {
    enum class QType : uint16_t {
        A       =  1,   // IPv4 address
        NS      =  2,   // Authoritative nameserver
        MD      =  3,   // Mail destination (obsolete, use MX)
        MF      =  4,   // Mail forwarder (obsolete, use MX)
        CNAME   =  5,   // Canonical name / alias
        SOA     =  6,   // Start of authority
        MB      =  7,   // Mailbox domain (experimental)
        MG      =  8,   // Mail group member (experimental)
        MR      =  9,   // Mail rename (experimental)
        NULL_   = 10,   // Null record (experimental)
        WKS     = 11,   // Well known service description
        PTR     = 12,   // Reverse DNS pointer
        HINFO   = 13,   // Host information (CPU + OS)
        MINFO   = 14,   // Mailbox / mail list info
        MX      = 15,   // Mail exchange
        TXT     = 16,   // Text record (SPF, DKIM, verification)
        RP      = 17,   // Responsible person
        AFSDB   = 18,   // AFS database location
        SIG     = 24,   // Security signature (old DNSSEC)
        KEY     = 25,   // Security key (old DNSSEC)
        AAAA    = 28,   // IPv6 address
        LOC     = 29,   // Geographic location
        SRV     = 33,   // Service locator (host + port)
        NAPTR   = 35,   // Naming authority pointer
        KX      = 36,   // Key exchanger
        CERT    = 37,   // Certificate record
        DNAME   = 39,   // Delegation name (subtree alias)
        OPT     = 41,   // EDNS0 options pseudo-RR
        APL     = 42,   // Address prefix list
        DS      = 43,   // DNSSEC delegation signer
        SSHFP   = 44,   // SSH public key fingerprint
        IPSECKEY= 45,   // IPsec key
        RRSIG   = 46,   // DNSSEC resource record signature
        NSEC    = 47,   // DNSSEC next secure record
        DNSKEY  = 48,   // DNSSEC public key
        DHCID   = 49,   // DHCP identifier
        NSEC3   = 50,   // DNSSEC next secure record v3
        NSEC3PARAM=51,  // NSEC3 parameters
        TLSA    = 52,   // TLS certificate association (DANE)
        SMIMEA  = 53,   // S/MIME certificate association
        HIP     = 55,   // Host identity protocol
        CDS     = 59,   // Child DS (for automatic DNSSEC)
        CDNSKEY = 60,   // Child DNSKEY
        OPENPGPKEY=61,  // OpenPGP public key
        CSYNC   = 62,   // Child-to-parent synchronization
        ZONEMD  = 63,   // Message digest for DNS zones
        SVCB    = 64,   // Service binding
        HTTPS   = 65,   // HTTPS service binding (RFC 9460)
        EUI48   = 108,  // MAC-48 address
        EUI64   = 109,  // EUI-64 address
        TKEY    = 249,  // Transaction key (for TSIG)
        TSIG    = 250,  // Transaction signature
        IXFR    = 251,  // Incremental zone transfer
        AXFR    = 252,  // Full zone transfer
        ANY     = 255,  // Any/all record types (deprecated in queries)
        URI     = 256,  // URI record
        CAA     = 257,  // Certification authority authorization
    };

    enum class QClass : uint16_t {
        IN_     =   1,  // Internet (the only one you'll ever see in practice)
        CS      =   2,  // CSNET (obsolete)
        CH      =   3,  // Chaos (used for meta queries e.g. version.bind)
        HS      =   4,  // Hesiod
        ANY     = 255,  // Any class
    };

    enum class RCode : uint8_t {
        NOERROR_  =  0,  // Success
        FORMERR  =  1,  // Format error — query malformed
        SERVFAIL =  2,  // Server failure — upstream unreachable etc.
        NXDOMAIN =  3,  // Non-existent domain ← your main block response
        NOTIMP   =  4,  // Not implemented
        REFUSED  =  5,  // Query refused by policy
        YXDOMAIN =  6,  // Name exists when it should not (dynamic DNS)
        YXRRSET  =  7,  // RR set exists when it should not
        NXRRSET  =  8,  // RR set does not exist
        NOTAUTH  =  9,  // Not authoritative for zone
        NOTZONE  = 10,  // Name not in zone
        BADSIG   = 16,  // TSIG signature failure
        BADKEY   = 17,  // Key not recognized
        BADTIME  = 18,  // Signature out of time window
        BADMODE  = 19,  // Bad TKEY mode
        BADNAME  = 20,  // Duplicate key name
        BADALG   = 21,  // Algorithm not supported
        BADTRUNC = 22,  // Bad truncation
        BADCOOKIE= 23,  // Bad/missing server cookie
    };

    enum class OpCode : uint8_t {
        QUERY  = 0,     // Standard query ← only one you'll ever receive
        IQUERY = 1,     // Inverse query (obsolete, RFC 3425)
        STATUS = 2,     // Server status request
        NOTIFY = 4,     // Zone change notification (RFC 1996)
        UPDATE = 5,     // Dynamic DNS update (RFC 2136)
        DSO    = 6,     // DNS stateful operations (RFC 8490)
    };

    namespace Flags {
        constexpr uint16_t QR      = 0x8000; // 1=response, 0=query
        constexpr uint16_t AA      = 0x0400; // Authoritative answer
        constexpr uint16_t TC      = 0x0200; // Truncated
        constexpr uint16_t RD      = 0x0100; // Recursion desired (client sets)
        constexpr uint16_t RA      = 0x0080; // Recursion available (server sets)
        constexpr uint16_t Z       = 0x0040; // Reserved, must be 0
        constexpr uint16_t AD      = 0x0020; // Authentic data (DNSSEC)
        constexpr uint16_t CD      = 0x0010; // Checking disabled (DNSSEC)
        constexpr uint16_t OPCODE  = 0x7800; // Opcode mask  (bits 14-11)
        constexpr uint16_t RCODE   = 0x000F; // Rcode mask   (bits 3-0)
    }

    namespace Port {
        constexpr uint16_t DNS     = 53;
        constexpr uint16_t DNS_TLS = 853;  // DNS over TLS (DoT)
    }

    namespace Limits {
        constexpr size_t   MAX_UDP_PACKET    = 512;   // Classic DNS max UDP
        constexpr size_t   MAX_EDNS_PAYLOAD  = 4096;  // EDNS0 extended UDP
        constexpr size_t   MAX_LABEL_LEN     = 63;    // Max single label length
        constexpr size_t   MAX_NAME_LEN      = 255;   // Max full domain name
        constexpr uint8_t  COMPRESSION_MASK  = 0xC0;  // Top 2 bits = pointer
        constexpr uint16_t COMPRESSION_PTR   = 0xC000;
    }

    enum class Error : uint16_t {

        // ── No error ─────────────────────────────────────────────────────────
        OK                  =  0,   // success

        // ── Parser errors ────────────────────────────────────────────────────
        PARSE_TOO_SHORT     = 10,   // packet smaller than 12-byte header
        PARSE_BAD_OPCODE    = 11,   // opcode not supported
        PARSE_BAD_LABEL     = 12,   // label length exceeds 63 bytes
        PARSE_NAME_TOO_LONG = 13,   // decoded name exceeds 255 bytes
        PARSE_PTR_LOOP      = 14,   // compression pointer loop detected
        PARSE_PTR_OOB       = 15,   // compression pointer out of bounds
        PARSE_TRUNCATED     = 16,   // packet ends mid-field
        PARSE_BAD_QTYPE     = 17,   // unrecognised QType value
        PARSE_BAD_QCLASS    = 18,   // unrecognised QClass value
        PARSE_BAD_QDCOUNT   = 19,   // QDCOUNT > 1 (unsupported)

        // ── Encoder errors ───────────────────────────────────────────────────
        ENCODE_NAME_TOO_LONG= 20,   // name exceeds 255 bytes
        ENCODE_LABEL_TOO_LONG=21,   // single label exceeds 63 bytes
        ENCODE_OVERFLOW     = 22,   // encoded packet exceeds max UDP size

        // ── Server errors ────────────────────────────────────────────────────
        SERVER_SOCKET_FAIL  = 30,   // failed to create UDP/TCP socket
        SERVER_BIND_FAIL    = 31,   // failed to bind to port
        SERVER_RECV_FAIL    = 32,   // recvfrom() returned error
        SERVER_SEND_FAIL    = 33,   // sendto() returned error
        SERVER_NOT_RUNNING  = 34,   // operation called before run()

        // ── Upstream / forwarding errors ─────────────────────────────────────
        UPSTREAM_TIMEOUT    = 40,   // upstream did not respond in time
        UPSTREAM_UNREACHABLE= 41,   // could not reach upstream resolver
        UPSTREAM_SERVFAIL   = 43,   // upstream returned SERVFAIL

        // ── Cache errors ─────────────────────────────────────────────────────
        CACHE_MISS          = 50,   // key not found in cache
        CACHE_EXPIRED       = 51,   // entry exists but TTL has elapsed
        CACHE_FULL          = 52,   // cache at max capacity, eviction needed

        // ── Blocklist errors ─────────────────────────────────────────────────
        BLOCKER_FILE_NOT_FOUND = 60, // blocklist file could not be opened
        BLOCKER_PARSE_ERROR    = 61, // malformed line in blocklist file
        BLOCKER_EMPTY          = 62, // blocklist loaded but contains 0 entries
        INVALID_IP             = 63, // invalid data provided
        // ── Unknown ──────────────────────────────────────────────────────────
        UNKNOWN             = 0xFF,
    };

    // Human-readable description for any Error code
    inline std::string errorToString(Error e) {
        switch (e) {
            case Error::OK:                    return "OK";
            case Error::PARSE_TOO_SHORT:       return "Packet too short";
            case Error::PARSE_BAD_OPCODE:      return "Unsupported opcode";
            case Error::PARSE_BAD_LABEL:       return "Label too long";
            case Error::PARSE_NAME_TOO_LONG:   return "Name too long";
            case Error::PARSE_PTR_LOOP:        return "Compression pointer loop";
            case Error::PARSE_PTR_OOB:         return "Compression pointer out of bounds";
            case Error::PARSE_TRUNCATED:       return "Packet truncated mid-field";
            case Error::PARSE_BAD_QTYPE:       return "Unrecognised QType";
            case Error::PARSE_BAD_QCLASS:      return "Unrecognised QClass";
            case Error::PARSE_BAD_QDCOUNT:     return "QDCOUNT > 1 unsupported";
            case Error::ENCODE_NAME_TOO_LONG:  return "Encode: name too long";
            case Error::ENCODE_LABEL_TOO_LONG: return "Encode: label too long";
            case Error::ENCODE_OVERFLOW:       return "Encode: packet overflow";
            case Error::SERVER_SOCKET_FAIL:    return "Socket creation failed";
            case Error::SERVER_BIND_FAIL:      return "Bind failed";
            case Error::SERVER_RECV_FAIL:      return "recvfrom() failed";
            case Error::SERVER_SEND_FAIL:      return "sendto() failed";
            case Error::SERVER_NOT_RUNNING:    return "Server not running";
            case Error::UPSTREAM_TIMEOUT:      return "Upstream timeout";
            case Error::UPSTREAM_UNREACHABLE:  return "Upstream unreachable";
            case Error::UPSTREAM_SERVFAIL:     return "Upstream SERVFAIL";
            case Error::CACHE_MISS:            return "Cache miss";
            case Error::CACHE_EXPIRED:         return "Cache entry expired";
            case Error::CACHE_FULL:            return "Cache full";
            case Error::BLOCKER_FILE_NOT_FOUND:return "Blocklist file not found";
            case Error::BLOCKER_PARSE_ERROR:   return "Blocklist parse error";
            case Error::BLOCKER_EMPTY:         return "Blocklist is empty";
            case Error::INVALID_IP:            return "Invalid IP address";
            default:                           return "Unknown error";
        }
    }

}
