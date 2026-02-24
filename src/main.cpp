#include "../include/server/server.hpp"
#include <print>
#include <span>
#include <string_view>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

void printUsage(std::string_view progName) {
    std::println("Usage: {} [OPTIONS] [BLOCKLIST_FILES...]", progName);
    std::println("");
    std::println("Options:");
    std::println("  --ip <addr>       Local IP to bind to        (default: 0.0.0.0)");
    std::println("  --port <port>     UDP port to listen on      (default: 53)");
    std::println("  --upstream <addr> Upstream resolver IP       (default: 8.8.8.8)");
    std::println("  --timeout <ms>    Upstream timeout (ms)      (default: 5000)");
    std::println("  --help            Show this message");
    std::println("");
    std::println("Blocklist path shorthands:");
    std::println("  ~/...             Home directory");
    std::println("  desktop/...       Desktop folder");
    std::println("  documents/...     Documents folder");
    std::println("  downloads/...     Downloads folder");
    std::println("  (relative paths are resolved from the current working directory)");
    std::println("");
    std::println("Example:");
    std::println("  {} --upstream 1.1.1.1 desktop/ads.txt ~/lists/malware.txt", progName);
}

// Returns the current user's home directory (USERPROFILE on Windows, HOME on Unix)
static fs::path homeDir() {
    if (const char* h = std::getenv("USERPROFILE"); h && *h) return h; // Windows
    if (const char* h = std::getenv("HOME");        h && *h) return h; // Unix
    return fs::current_path(); // fallback
}

/**
 * Resolves shorthand and relative path forms to an absolute fs::path.
 *
 *  ~/...          ->  <home>/...
 *  desktop/...    ->  <home>/Desktop/...
 *  documents/...  ->  <home>/Documents/...
 *  downloads/...  ->  <home>/Downloads/...
 *  <other>        ->  absolute() relative to cwd
 */
static fs::path resolvePath(std::string_view raw) {
    // Normalise separators: replace all '/' with the native separator on Windows
    std::string s(raw);
    for (char& c : s)
        if (c == '/') c = fs::path::preferred_separator;

    fs::path p(s);

    // ~ expansion
    if (s.starts_with("~")) {
        p = homeDir() / fs::path(s.substr(2)); // skip "~/"
        return p;
    }

    // Named shorthand prefixes (case-insensitive compare on the first component)
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    auto replacePrefix = [&](std::string_view prefix, std::string_view folder) -> fs::path {
        if (lower.starts_with(prefix))
            return homeDir() / folder / fs::path(s.substr(prefix.size()));
        return {};
    };

    if (auto r = replacePrefix("desktop\\",   "Desktop");   !r.empty()) return r;
    if (auto r = replacePrefix("documents\\", "Documents"); !r.empty()) return r;
    if (auto r = replacePrefix("downloads\\", "Downloads"); !r.empty()) return r;

    // Plain relative or absolute path
    return fs::absolute(p);
}

int main(int argc, char* argv[]) {
    DNS::Server::Config config{
        .serverIp     = "0.0.0.0",
        .portServerIp = 53,
        .upstreamIp   = "8.8.8.8",
        .timeout_ms   = 5000,
    };

    std::vector<std::string> blocklistFiles;
    auto args = std::span(argv, argc);

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = args[i];

        if (arg == "--help" || arg == "-h") {
            printUsage(args[0]); return 0;
        }
        else if (arg == "--ip") {
            if (++i >= argc) { std::println(stderr, "[ERROR] --ip requires an argument.");      return 1; }
            config.serverIp = args[i];
        }
        else if (arg == "--port") {
            if (++i >= argc) { std::println(stderr, "[ERROR] --port requires an argument.");    return 1; }
            try { config.portServerIp = static_cast<uint16_t>(std::stoul(args[i])); }
            catch (...) { std::println(stderr, "[ERROR] Invalid port: {}", args[i]);             return 1; }
        }
        else if (arg == "--upstream") {
            if (++i >= argc) { std::println(stderr, "[ERROR] --upstream requires an argument."); return 1; }
            config.upstreamIp = args[i];
        }
        else if (arg == "--timeout") {
            if (++i >= argc) { std::println(stderr, "[ERROR] --timeout requires an argument."); return 1; }
            try { config.timeout_ms = static_cast<uint32_t>(std::stoul(args[i])); }
            catch (...) { std::println(stderr, "[ERROR] Invalid timeout: {}", args[i]);          return 1; }
        }
        else if (arg.starts_with("--")) {
            std::println(stderr, "[ERROR] Unknown option: {}", arg);
            printUsage(args[0]); return 1;
        }
        else {
            // Resolve and validate the path before handing it off
            fs::path resolved = resolvePath(arg);
            if (!fs::exists(resolved)) {
                std::println(stderr, "[WARN] Blocklist file not found, skipping: {}", resolved.string());
                continue;
            }
            std::println("[INFO] Blocklist: {} -> {}", arg, resolved.string());
            blocklistFiles.push_back(resolved.string());
        }
    }

    std::println("[INFO] Binding to        {}:{}", config.serverIp, config.portServerIp);
    std::println("[INFO] Upstream resolver {}", config.upstreamIp);
    std::println("[INFO] Upstream timeout  {} ms", config.timeout_ms);

    DNS::Server::Listener server;

    if (!blocklistFiles.empty()) {
        std::println("[INFO] Loading {} blocklist file(s)...", blocklistFiles.size());
        if (auto err = server.loadBlocklist(blocklistFiles); err != DNS::Error::OK) {
            std::println(stderr, "[ERROR] {}", DNS::errorToString(err));
            return 1;
        }
        std::println("[INFO] Blocklist loaded.");
    } else {
        std::println("[WARN] No blocklist files provided — all queries will be forwarded.");
    }

    if (auto err = server.init(config); err != DNS::Error::OK) {
        std::println(stderr, "[ERROR] init(): {}", DNS::errorToString(err));
        return 1;
    }

    if (auto err = server.run(); err != DNS::Error::OK) {
        std::println(stderr, "[ERROR] run():  {}", DNS::errorToString(err));
        return 1;
    }

    return 0;
}
