/*
* Copyright 2025 Dynatrace LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License cat
*
* https://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
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
    uint16_t getServerPort() const {
        return serverPort;
    }
    void randomizeServerPort();

private:
    bool serverRunning() const {
        return serverThreadReturn.valid();
    }
    bool clientRunning() const {
        return static_cast<bool>(connection);
    }

    std::future<bool> serverThreadReturn;
    SocketFD connection = {nullptr, nullptr};
    uint16_t serverPort = 1234;
    uint16_t clientPort = 0;
};

namespace detail {

uint16_t connectSendClose(char msg, uint16_t port);
std::pair<SocketFD, uint16_t> connectSendKeep(int reps, uint16_t port);

SocketFD createSocket();
void setsockoptLinger(int fd);
void setsockoptNodelay(int fd);
void setsockoptReuseaddr(int fd);
sockaddr_in createSocketAddress(int fd, uint16_t port);

void connectSocket(int fd, sockaddr_in* socketAddress);
void bindListenOnSocket(int fd, sockaddr_in* socketAddress);
SocketFD acceptOnSocket(int fd);

void writeMessage(int fd, char msg);

} // namespace detail
