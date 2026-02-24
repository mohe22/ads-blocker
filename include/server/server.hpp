#pragma once
#include <WinSock2.h> // socket
#include <ws2tcpip.h> // inet_ntop
#include <vector>
#include <cstdint>
#include <unordered_set>
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define RESET   "\x1b[0m"


#include "../parser/common.hpp"

namespace DNS::Server {

    /**
     * @brief Holds configuration parameters for the DNS listener.
     *
     * @param serverIp    The local IP address to bind the listener to. Defaults to "0.0.0.0" (all interfaces).
     * @param portServerIp The UDP port to listen on. Defaults to 53 (standard DNS port).
     * @param upstreamIp  The IP address of the upstream DNS resolver to forward queries to. Defaults to "8.8.8.8" (Google DNS).
     * @param timeout_ms  How long (in milliseconds) to wait for a response from the upstream resolver before giving up. Defaults to 5000ms.
     */
    struct Config {
        std::string serverIp   = "127.0.0.1";
        uint16_t  portServerIp = 53;
        std::string upstreamIp = "8.8.8.8";
        uint32_t timeout_ms    = 5000;
    };

    class Listener {
    public:
        /**
         * @brief Destructor. Closes both the listener and upstream sockets and shuts down Winsock.
         *
         * Ensures all sockets are released cleanly via closeSocket(), then calls WSACleanup()
         * to free Winsock resources.
         */
        ~Listener() noexcept;

        /**
         * @brief Initialises Winsock, binds the listener socket, and configures the upstream resolver socket.
         *
         * Steps performed:
         *  - Stores the supplied configuration.
         *  - Calls WSAStartup to initialise Winsock 2.2.
         *  - Creates a UDP socket and binds it to cfg.serverIp:cfg.portServerIp.
         *  - Creates a second UDP socket pointed at cfg.upstreamIp:53.
         *  - Applies a receive timeout (cfg.timeout_ms) to the upstream socket so a
         *    dead resolver never blocks indefinitely.
         *
         * @param cfg Configuration to use. If omitted the default Config{} is applied.
         * @return DNS::Error::OK on success, or one of:
         *         SERVER_SOCKET_FAIL – WSAStartup or socket() failed.
         *         INVALID_IP         – serverIp or upstreamIp is not a valid IPv4 address.
         *         SERVER_BIND_FAIL   – bind() failed on the listener socket.
         */
        DNS::Error init(const Config &cfg = {}) noexcept;

        /**
         * @brief Enters the main event loop, processing incoming DNS queries indefinitely.
         *
         * Calls handleQuery() in a tight loop. Non-fatal errors are logged as warnings
         * and the loop continues. This function never returns under normal operation.
         *
         * @return DNS::Error::SERVER_NOT_RUNNING if init() was never called (socket is invalid).
         */
        DNS::Error run() noexcept;

        /**
         * @brief Loads one or more blocklist files and populates the internal blocklist set.
         *
         * Each file should contain one domain per line. Lines are lower-cased before
         * insertion. Duplicate entries are silently ignored (unordered_set semantics).
         *
         * @param files A list of file paths to load.
         * @return DNS::Error::OK on success, or DNS::Error::BLOCKER_FILE_NOT_FOUND if
         *         any file cannot be opened (loading stops at the first failure).
         */
        DNS::Error loadBlocklist(const std::vector<std::string> &files) noexcept;

    private:
        SOCKET      socket_   { INVALID_SOCKET };
        SOCKET      upstream_ { INVALID_SOCKET };
        sockaddr_in upstreamAddr_ {};
        Config      cfg_;
        std::unordered_set<std::string> blocklist_;

        /**
         * @brief Safely closes a socket and resets the handle to INVALID_SOCKET.
         *
         * A no-op if the socket is already INVALID_SOCKET, preventing double-close.
         *
         * @param s Reference to the SOCKET handle to close. Set to INVALID_SOCKET after closing.
         */
        void closeSocket(SOCKET &s) noexcept;

        /**
         * @brief Receives a single DNS query, parses it, and forwards it upstream.
         *
         * Steps performed:
         *  - Blocks on recvfrom() waiting for a UDP datagram on the listener socket.
         *  - Validates the minimum message length (>= 13 bytes).
         *  - Parses the datagram into a DNS::Parser::Message.
         *  - Logs and forwards each question in the message via forward().
         *
         * @return DNS::Error::OK on success, or one of:
         *         SERVER_RECV_FAIL – recvfrom() failed.
         *         PARSE_TOO_SHORT  – datagram is shorter than the minimum DNS header size.
         *         Any error returned by the parser or forward().
         */
        DNS::Error handleQuery() noexcept;



        /**
         * @brief Forwards a raw DNS query to the upstream resolver and relays the response back to the client.
         *
         * Steps performed:
         *  - Sends the raw query buffer to the configured upstream resolver via sendto().
         *  - Waits for the upstream response (subject to the configured timeout).
         *  - Sends the upstream response back to the original client.
         *
         * @param data   Pointer to the raw DNS query bytes to forward.
         * @param len    Number of bytes in the query buffer.
         * @param client The sockaddr_in of the original querying client, used to send the reply back.
         * @return DNS::Error::OK on success, or one of:
         *         UPSTREAM_UNREACHABLE – upstream socket is invalid or sendto() failed.
         *         UPSTREAM_TIMEOUT     – the upstream resolver did not respond within timeout_ms.
         *         SERVER_SEND_FAIL     – sending the response back to the client failed.
         */
        DNS::Error forward(const uint8_t *data, size_t len, const sockaddr_in &client) noexcept;

        /**
         * @brief Strips the scheme/protocol prefix from a URL in-place.
         *
         * Finds the first occurrence of "://" and removes everything up to
         * and including it, leaving only the host and beyond.
         *
         * @param str The URL string to modify in-place.
         *
         * @example
         *   "https://example.com"  ->  "example.com"
         *   "ftp://files.net/path" ->  "files.net/path"
         *   "example.com"          ->  "example.com"   (no-op, no scheme found)
         */
        void stripSchema(std::string &str) noexcept;

        /**
         * @brief Strips the path, query string, port, and fragment from a URL in-place.
         *
         * Scans for the first boundary character ('/', '?', ':', '#') and erases
         * everything from that position to the end of the string, isolating
         * the bare hostname.
         *
         * @param str The URL string (scheme already stripped) to modify in-place.
         *
         * @example
         *   "example.com/path?q=1" ->  "example.com"
         *   "example.com:8080"     ->  "example.com"
         *   "example.com#anchor"   ->  "example.com"
         *   "example.com"          ->  "example.com"   (no-op, no boundary found)
         */
        void stripPathAndQuery(std::string &str) noexcept;

        /**
         * @brief Strips subdomains from a fully-qualified domain name to find a blocklist match.
         *
         * Iteratively removes the leftmost label (subdomain) until either a match
         * is found in the blocklist or only the bare TLD remains (no dot left).
         * stripSchema() and stripPathAndQuery() are applied first to normalise the input.
         *
         * @param domain The domain or URL to search for in the blocklist.
         * @return true  if the domain or any of its parent domains is in the blocklist.
         *         false if no match was found.
         *
         * @example
         *   blocklist = { "example.com", "ads.net" }
         *   "sub.example.com"  ->  true   (matched after 1 strip)
         *   "a.b.ads.net"      ->  true   (matched after 2 strips)
         *   "unknown.org"      ->  false  (no match)
         */
        bool search(const std::string &domain) noexcept;
    };

} // namespace DNS::Server
