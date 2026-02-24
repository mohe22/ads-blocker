#include "../include/server/server.hpp"

#include <print>
int main(){

    DNS::Server::Config config{
        .serverIp = "0.0.0.0",
        .portServerIp = 53,
        .upstreamIp = "8.8.8.8",
        .timeout_ms = 5000,
    };

    DNS::Server::Listener server;
    auto error = server.loadBlocklist({"adBlockerlist.txt"});
    if(error != DNS::Error::OK) {
        std::println("[ERROR] {}", DNS::errorToString(error));
    } ;

    server.init(config);
    server.run();

    return 0;
}
