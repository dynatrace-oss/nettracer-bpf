#pragma once

#include <spdlog/fwd.h>
#include <cstdint>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

struct sockaddr_in;
struct tcp_info;

class SocketException : public std::runtime_error {
public:
    explicit SocketException(int fd, const std::string& error);
};

using SocketFD = std::unique_ptr<int, void(*)(int*)>;
SocketFD createSocketFD(int fd);

// class which combines client and server, needed for guessing most offsets
class LocalSock {
public:
    LocalSock();
    virtual ~LocalSock();

    bool startServer();
    bool stopServer();

    bool startClient();
    bool stopClient();

    bool start();
    bool stop();

    bool running() const {
        return serverRunning() && clientRunning();
    }

    tcp_info getTCPInfo();
    inline uint16_t getClientPort() const {
        return clientPort;
    }

    static inline const char* serverAddress = "127.0.0.2";
    static inline const int serverPort = 1234;

private:
    bool serverRunning() const {
        return serverThreadReturn.valid();
    }
    bool clientRunning() const {
        return static_cast<bool>(connection);
    }

    std::future<bool> serverThreadReturn;
    SocketFD connection = {nullptr, nullptr};
    uint16_t clientPort = 0;
};

namespace detail {

uint16_t connectSendClose(char msg);
std::pair<SocketFD, uint16_t> connectSendKeep(int reps);

SocketFD createSocket();
void setsockoptLinger(int fd);
void setsockoptNodelay(int fd);
void setsockoptReuseaddr(int fd);
sockaddr_in createSocketAddress(int fd);

void connectSocket(int fd, sockaddr_in* socketAddress);
void bindListenOnSocket(int fd, sockaddr_in* socketAddress);
SocketFD acceptOnSocket(int fd);

void writeMessage(int fd, char msg);

} // namespace detail
