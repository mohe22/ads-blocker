#include "../../include/server/server.hpp"
#include "../../include/parser/parser.hpp"

#include <print>
#include <fstream>

// TODO Handle:
// Windows-only: when a previous sendto() reaches a client that already closed
// its port, Windows injects an ICMP error back into this socket, causing the
// next recvfrom() to fail with WSAECONNRESET.
// On Linux this never happens so no equivalent is needed.

namespace DNS::Server {
    Listener::~Listener() noexcept {
        closeSocket(socket_);
        closeSocket(upstream_);
        WSACleanup();
    }

    void Listener::closeSocket(SOCKET &s) noexcept {
        if (s != INVALID_SOCKET) {
            closesocket(s);
            s = INVALID_SOCKET;
        }
    }

    DNS::Error Listener::init(const Config &cfg) noexcept {
        cfg_ = cfg;

        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return DNS::Error::SERVER_SOCKET_FAIL;

        closeSocket(socket_);
        closeSocket(upstream_);
        socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_ == INVALID_SOCKET)
            return DNS::Error::SERVER_SOCKET_FAIL;


        sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_port = htons(cfg_.portServerIp);

        if (inet_pton(AF_INET, cfg_.serverIp.c_str(), &bindAddr.sin_addr) != 1) {
            closeSocket(socket_);
            return DNS::Error::INVALID_IP;
        }
        if (bind(socket_, reinterpret_cast<sockaddr *>(&bindAddr),
                sizeof(bindAddr)) == SOCKET_ERROR) {
            closeSocket(socket_);
            return DNS::Error::SERVER_BIND_FAIL;
        }

        upstream_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (upstream_ == INVALID_SOCKET) {
            closeSocket(socket_);
            return DNS::Error::SERVER_SOCKET_FAIL;
        }

        upstreamAddr_.sin_family = AF_INET;
        upstreamAddr_.sin_port = htons(DNS::Port::DNS);

        if (inet_pton(AF_INET, cfg_.upstreamIp.c_str(), &upstreamAddr_.sin_addr) != 1) {
            closeSocket(socket_);
            closeSocket(upstream_);
            return DNS::Error::INVALID_IP;
        }

        // Apply a receive timeout on the upstream socket so a dead resolver
        // never stalls the listener indefinitely.
        DWORD timeout = cfg_.timeout_ms;
        setsockopt(upstream_, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<const char *>(&timeout), sizeof(timeout));

        std::println(GREEN "[INFO] Listener bound to {}:{}" RESET, cfg_.serverIp, cfg_.portServerIp);
        std::println(GREEN "[INFO] Upstream resolver : {}" RESET, cfg_.upstreamIp);
        return DNS::Error::OK;
    }

    DNS::Error Listener::loadBlocklist(const std::vector<std::string> &files) noexcept {
        for (const auto &fileName : files) {
            std::ifstream file(fileName);
            if (!file.is_open()) {
                std::println(YELLOW "[WARN] Could not open blocklist file: {}" RESET, fileName);
                return DNS::Error::BLOCKER_FILE_NOT_FOUND;
            }
            std::string line;
            while (std::getline(file, line)) {
                std::transform(line.begin(), line.end(), line.begin(),
                                [](unsigned char c) { return std::tolower(c); });
                blocklist_.insert(line);
            }
        }
        std::println(GREEN "[INFO] Blocklist loaded , {} domain(s) total" RESET, blocklist_.size());
        return DNS::Error::OK;
    }

    DNS::Error Listener::run() noexcept {
        if (socket_ == INVALID_SOCKET)
            return DNS::Error::SERVER_NOT_RUNNING;

        std::println(GREEN "[INFO] Listener running , waiting for queries..." RESET);

        for (;;) {
            if (auto err = handleQuery(); err != DNS::Error::OK) {
                std::println(YELLOW "[WARN] handleQuery error: {}" RESET, DNS::errorToString(err));
            }
        }
    }


    DNS::Error Listener::handleQuery() noexcept {
        DNS::Parser::MessageParser parser;
        uint8_t buf[DNS::Limits::MAX_EDNS_PAYLOAD]{};
        sockaddr_in client{};
        int clientLen = sizeof(client);

        // 1. Receive
        // Block until a UDP datagram arrives on the bound socket.
        // recvfrom fills `client` with the sender's address so we can reply later.
        const int received = recvfrom(
            socket_, reinterpret_cast<char *>(buf), sizeof(buf), 0,
            reinterpret_cast<sockaddr *>(&client), &clientLen);

        if (received == SOCKET_ERROR)
            return DNS::Error::SERVER_RECV_FAIL;

        // A valid DNS message requires at least a 12-byte header plus 1 byte of question data.
        if (received < 13)
            return DNS::Error::PARSE_TOO_SHORT;

        // 2. Parse
        // Decode the raw bytes into a structured Message (header + questions + resource records).
        // Malformed packets are rejected here , we never forward garbage upstream.
        std::expected<DNS::Parser::Message, DNS::Error> result = parser.parse(buf, received);
        if (!result.has_value())
            return result.error();

        // 3. Inspect questions
        // RFC 1035 permits multiple questions per message, but real resolvers always send one.
        // We iterate anyway for correctness; the first blocked name short-circuits the loop.
        for (const auto& q : result.value().getQuestions()) {
            std::println(GREEN "[QUERY] {} asked for: {} (type {})" RESET,
                inet_ntoa(client.sin_addr), q.getName(), static_cast<uint16_t>(q.getType()));

            // 4. Blocklist check
            // search() walks up the label hierarchy, so blocking "ads.example.com"
            // also catches "sub.ads.example.com".
            if (search(q.getName())) {

                // 5. Build a blocked response in-place
                //   QR=1  → marks this packet as a response
                //   RA=1  → advertises recursion support (mirrors a real resolver)
                //   AA=0  → we are not authoritative for this zone
                //   RCODE stays NOERROR , some stub resolvers treat NXDOMAIN as a hard failure,
                //                         so NOERROR with a null answer is the safer lie.
                result.value().getHeader().setQr(true);
                result.value().getHeader().setRa(true);

                // Clear authority and additional sections , they would belong to the real zone
                // and are meaningless in a blocked response.
                result.value().getHeader().setAuthorities(0);
                result.value().getHeader().setAdditionals(0);

                if (q.getType() == DNS::QType::HTTPS) {
                    // HTTPS records (type 65) carry rich metadata: ALPN lists, ECH keys,
                    // address hints, etc. Fabricating a structurally valid HTTPS RR is not
                    // feasible , a browser receiving a malformed one will retry and log errors.
                    // Responding with ANCOUNT=0 and NOERROR is the cleanest option:
                    // "no HTTPS record exists" , browsers accept it silently and fall back
                    // to a plain A/AAAA lookup, which we will also intercept.
                    result.value().getHeader().setAnswers(0);
                } else {
                    // For all other record types we return a null-route answer:
                    //   A    →  0.0.0.0   (4 zero bytes)
                    //   AAAA →  ::        (16 zero bytes)
                    //   Other types still receive 4 zero bytes; clients that do not
                    //   understand the type will discard the rdata.
                    // TTL=0 prevents the null record from being cached, so the block
                    // takes effect immediately if the domain is later removed from the list.
                    DNS::Parser::ResourceRecord rr;
                    rr.setName   (q.getName());
                    rr.setType   (q.getType());
                    rr.setRclass (q.getClass());
                    rr.setTtl    (0);

                    const uint16_t rdlen = (q.getType() == DNS::QType::AAAA) ? 16 : 4;
                    rr.setRdlength(rdlen);
                    rr.setRdata(std::vector<uint8_t>(rdlen, 0x00));

                    result.value().setAnswers({rr});
                    result.value().getHeader().setAnswers(1);
                }

                // 6. Encode & send the blocked response
                auto encoded = DNS::Parser::MessageParser::encode(result.value());
                if (!encoded) {
                    std::println(YELLOW "[WARN] Failed to encode blocked response for '{}': {}" RESET,
                        q.getName(), DNS::errorToString(encoded.error()));
                    return encoded.error();
                }

                // Sanity check: the encoded size must fit within a single UDP datagram.
                // This should never trigger for our small synthetic records, but we guard
                // defensively before passing raw sizes to the Winsock API.
                if (encoded->size() > DNS::Limits::MAX_EDNS_PAYLOAD) {
                    std::println(YELLOW "[WARN] Blocked response for '{}' exceeds max payload ({} bytes) , dropping" RESET,
                        q.getName(), encoded->size());
                    return DNS::Error::SERVER_SEND_FAIL;
                }

                const int sent = sendto(
                    socket_,
                    reinterpret_cast<const char*>(encoded->data()),
                    encoded->size(),
                    0,
                    reinterpret_cast<const sockaddr*>(&client),
                    sizeof(client));

                if (sent == SOCKET_ERROR) {

                    std::println(YELLOW "[WARN] sendto failed for blocked '{}' , WSA error {}" RESET,
                        q.getName(), WSAGetLastError());
                    return DNS::Error::SERVER_SEND_FAIL;
                }

                if (sent !=encoded->size()) {
                    // UDP sendto is atomic , the entire datagram is sent or the call fails.
                    // A partial send is theoretically impossible, but we log it as a sanity check.
                    std::println(YELLOW "[WARN] Partial send for blocked '{}': {} of {} bytes sent" RESET,
                        q.getName(), sent, encoded->size());
                    return DNS::Error::SERVER_SEND_FAIL;
                }

                std::println(RED "[BLOCKED] {} , null response sent to {} ({} bytes)" RESET,
                    q.getName(), inet_ntoa(client.sin_addr), sent);
                return Error::OK;
            }

            // 7. Forward
            // Domain is not blocked , relay the original raw datagram to the upstream
            // resolver and pipe the response straight back to the client.
            if (auto err = forward(buf, received, client); err != Error::OK) {
                std::println(YELLOW "[WARN] Forward failed for '{}': {}" RESET,
                    q.getName(), DNS::errorToString(err));
            }
        }

        return Error::OK;
    }


    DNS::Error Listener::forward(const uint8_t *data, const size_t len, const sockaddr_in &client) noexcept {
        if (upstream_ == INVALID_SOCKET)
            return DNS::Error::UPSTREAM_UNREACHABLE;

        const int sent = sendto(upstream_, reinterpret_cast<const char *>(data),
                                len, 0,
                                reinterpret_cast<const sockaddr *>(&upstreamAddr_),
                                sizeof(upstreamAddr_));
        if (sent == SOCKET_ERROR)
            return DNS::Error::UPSTREAM_UNREACHABLE;

        std::println(GREEN "[FORWARD] Query sent to upstream {}" RESET, inet_ntoa(upstreamAddr_.sin_addr));

        uint8_t response[DNS::Limits::MAX_EDNS_PAYLOAD]{};
        sockaddr_in from{};
        int fromLen = sizeof(from);

        const int respLen = recvfrom(upstream_, reinterpret_cast<char *>(response),
                                    sizeof(response), 0,
                                    reinterpret_cast<sockaddr *>(&from), &fromLen);

        if (respLen == SOCKET_ERROR) {
            const int err = WSAGetLastError();
            if (err == WSAETIMEDOUT)
                std::println(YELLOW "[WARN] Upstream {} timed out" RESET, inet_ntoa(upstreamAddr_.sin_addr));
            else
                std::println(YELLOW "[WARN] Upstream {} unreachable , WSA error {}" RESET, inet_ntoa(upstreamAddr_.sin_addr), err);

            return (err == WSAETIMEDOUT) ? DNS::Error::UPSTREAM_TIMEOUT
                                        : DNS::Error::UPSTREAM_UNREACHABLE;
        }

        std::println(GREEN "[FORWARD] Response received from upstream {} ({} bytes) , relaying to {}" RESET,
            inet_ntoa(upstreamAddr_.sin_addr), respLen, inet_ntoa(client.sin_addr));

        const int fwd = sendto(socket_, reinterpret_cast<const char *>(response), respLen, 0,
                    reinterpret_cast<const sockaddr *>(&client), sizeof(client));
        if (WSAGetLastError() == WSAECONNRESET)
            return DNS::Error::OK;

        return (fwd == SOCKET_ERROR) ? DNS::Error::SERVER_SEND_FAIL : DNS::Error::OK;
    }

    void Listener::stripPathAndQuery(std::string &str) noexcept {
        size_t pos = str.find_first_of("/?:#");
        if (pos != std::string::npos)
            str.erase(pos);
    }

    void Listener::stripSchema(std::string &str) noexcept {
        size_t pos = str.find("://");
        if (pos != std::string::npos)
            str.erase(0, pos + 3);
    }

    bool Listener::search(const std::string& domain) noexcept {
        std::string current = domain;
        stripSchema(current);
        stripPathAndQuery(current);

        std::transform(current.begin(), current.end(), current.begin(),
                       [](unsigned char c){ return std::tolower(c); });

        while (true) {
            if (blocklist_.contains(current))
                return true;
            size_t dot = current.find('.');
            if (dot == std::string::npos)
                return false;
            current = current.substr(dot + 1);
        }
    }

} // namespace DNS::Server
