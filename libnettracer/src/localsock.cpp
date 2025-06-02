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
#include "localsock.h"

#include "bpf_generic/src/log.h"

#include <fmt/core.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

const char msgContinue = 'c';
const char msgBreak = 'b';
const char msgExit = 'x';
const auto serverStartStopTimeout = std::chrono::seconds(5);

bool setUpServer(std::promise<bool> startPromise, uint16_t port, SocketFD& fd) {
	using namespace detail;
	using namespace std::chrono;

	auto startTime{steady_clock::now()};
	LOG_DEBUG("Starting server on {}:{:d}", LocalSock::serverAddress, port);
	try {
		fd = createSocket();
		setsockoptReuseaddr(*fd);
		auto socketAddress{createSocketAddress(*fd, port)};
		bindListenOnSocket(*fd, &socketAddress);
	}
	catch (const SocketException& ex) {
		LOG_ERROR("Server failed to start");
		LOG_ERROR(ex.what());
		startPromise.set_value(false);
		return false;
	}
	catch (...) {
		startPromise.set_exception(std::current_exception());
		return false;
	}

	startPromise.set_value(true);
	if (duration_cast<seconds>(steady_clock::now() - startTime) >= serverStartStopTimeout) {
		LOG_ERROR("Server start timeout reached, stopping");
		return false;
	}
	return true;
}

bool handleConnections(const SocketFD& fd) {
	using namespace detail;

	while (true) {
		try {
			auto fdc{acceptOnSocket(*fd)};
			char msg{msgContinue};
			while (msg == msgContinue) {
				if (read(*fdc, &msg, 1) == -1) {
					if (errno == EBADF || errno == ECONNRESET) {
						LOG_WARN("read failed (EBADF or ECONNRESET)");
						continue;
					}
					throw SocketException{*fdc, "read failed"};
				}
			}

			if (msg == msgExit) {
				LOG_DEBUG("Server finished");
				return true;
			}
		}
		catch (const SocketException& ex) {
			LOG_ERROR("Server failed to handle an incoming connection");
			LOG_ERROR(ex.what());
			return false;
		}
	}
}

void listenForConnections(std::promise<bool> startPromise, std::promise<bool> returnPromise, uint16_t port) {
	try {
		SocketFD fd{nullptr, nullptr};
		if (!setUpServer(std::move(startPromise), port, fd)) {
			returnPromise.set_value_at_thread_exit(false);
			return;
		}

		returnPromise.set_value_at_thread_exit(handleConnections(fd));
	}
	catch (...) {
		returnPromise.set_exception_at_thread_exit(std::current_exception());
	}
}

}
SocketException::SocketException(int fd, const std::string& error) :
	std::runtime_error(fmt::format("Failure for socket with fd={:d}: {}, errno: {:d} ({})", fd, error, errno, strerror(errno))) {}

SocketFD createSocketFD(int fd) {
	return SocketFD{new int{fd}, [](int* fd){ close(*fd); delete fd; }};
}

LocalSock::LocalSock() {
	start();
}

LocalSock::~LocalSock() {
	if (serverRunning()) {
		stop();
	}
}

bool LocalSock::startServer() {
	if (serverRunning()) {
		return false;
	}

	std::promise<bool> startPromise;
	auto startSuccessful = startPromise.get_future();

	// have to use a detached thread - dtor of future from std::async blocks until state is ready
	std::promise<bool> returnPromise;
	auto temporaryServerReturn = returnPromise.get_future();
	std::thread{listenForConnections, std::move(startPromise), std::move(returnPromise), getServerPort()}.detach();

	auto waitStatus = startSuccessful.wait_for(serverStartStopTimeout);
	if (waitStatus != std::future_status::ready) {
		LOG_ERROR("Server took too much time to start");
		return false;
	}

	try {
		if (!startSuccessful.get()) {
			return false;
		}
	}
	catch (const std::exception& ex) {
		LOG_ERROR("Unexpected error occurred during server start: {}", ex.what());
		return false;
	}

	serverThreadReturn = std::move(temporaryServerReturn);
	return serverThreadReturn.valid();
}

bool LocalSock::stopServer() {
	if (!serverRunning()) {
		return false;
	}

	try {
		detail::connectSendClose(msgExit, getServerPort());
	}
	catch (const SocketException& ex) {
		LOG_ERROR(ex.what());
		return false;
	}
	auto waitStatus = serverThreadReturn.wait_for(serverStartStopTimeout);
	if (waitStatus != std::future_status::ready) {
		LOG_ERROR("Server took too much time to stop");
		return false;
	}

	try {
		(void)serverThreadReturn.get();
	}
	catch (const std::exception& ex) {
		LOG_ERROR("Unexpected error occurred during server run time: {}", ex.what());
	}
	return true;
}

bool LocalSock::startClient() {
	if (clientRunning()) {
		return false;
	}

	try {
		auto ret{detail::connectSendKeep(377, getServerPort())}; // "random" number of "messages"
		connection = std::move(ret.first);
		clientPort = ret.second;
		return true;
	}
	catch (const SocketException& ex) {
		LOG_ERROR(ex.what());
		return false;
	}
}

bool LocalSock::stopClient() {
	if (!clientRunning()) {
		return false;
	}

	connection.reset();
	clientPort = 0;
	return true;
}

bool LocalSock::start() {
	if (!startServer()) {
		return false;
	}
	bool clientStarted{startClient()};
	if (!clientStarted) {
		stopServer();
	}
	return clientStarted;
}

bool LocalSock::stop() {
	bool clientStopped{stopClient()};
	bool serverStopped{stopServer()};
	return clientStopped && serverStopped;
}

tcp_info LocalSock::getTCPInfo() {
    tcp_info ti;
    socklen_t tcp_info_len{sizeof(tcp_info)};

    if (getsockopt(*connection, IPPROTO_TCP, TCP_INFO, (void*)&ti, &tcp_info_len) < 0) {
        throw SocketException{*connection, "getsockopt TCP_INFO failed"};
    }
    return ti;
}

void LocalSock::randomizeServerPort() {
	const uint16_t begin{1024}, end{65535};
	serverPort = begin + rand() % (end - begin + 1);
}

namespace detail {

uint16_t connectSendClose(char msg, uint16_t port) {
	auto fd{createSocket()};
	setsockoptLinger(*fd);
	auto socketAddress{createSocketAddress(*fd, port)};
	connectSocket(*fd, &socketAddress);
	writeMessage(*fd, msg);
	// return source port in network order
	return socketAddress.sin_port;
}

std::pair<SocketFD, uint16_t> connectSendKeep(int reps, uint16_t port) {
	auto fd{createSocket()};
	setsockoptNodelay(*fd);
	auto socketAddress{createSocketAddress(*fd, port)};
	connectSocket(*fd, &socketAddress);
	while (reps-- > 0) {
		writeMessage(*fd, msgContinue);
	}
	writeMessage(*fd, msgBreak);
	// return socket fd and source port in network order
	return std::make_pair<SocketFD, uint16_t>(std::move(fd), std::move(socketAddress.sin_port));
}

SocketFD createSocket() {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		throw SocketException{fd, "socket creation failed"};
	}
	return createSocketFD(fd);
}

void setsockoptLinger(int fd) {
	linger so_linger;
	so_linger.l_linger = 1;
	so_linger.l_onoff = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));
	if (ret != 0) {
		throw SocketException{fd, fmt::format("setsockopt (SO_LINGER) failed, error={:d}", ret)};
	}
}

void setsockoptNodelay(int fd) {
	int flag = 1;
	int ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	if (ret != 0) {
		throw SocketException{fd, fmt::format("setsockopt (TCP_NODELAY) failed, error={:d}", ret)};
	}
}

void setsockoptReuseaddr(int fd) {
	int so_reuseaddr = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr));
	if (ret != 0) {
		throw SocketException{fd, fmt::format("setsockopt (SO_REUSEADDR) failed, error={:d}", ret)};
	}
}

sockaddr_in createSocketAddress(int fd, uint16_t port) {
	sockaddr_in socketAddress;
	in_addr addr;
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_port = htons(port);
	if (inet_aton(LocalSock::serverAddress, &addr) == 0) {
		throw SocketException{fd, fmt::format("inet_aton failed: address={}", LocalSock::serverAddress)};
	}
	socketAddress.sin_addr.s_addr = addr.s_addr;
	return socketAddress;
}

void connectSocket(int fd, sockaddr_in* socketAddress) {
	if (connect(fd, (sockaddr*)socketAddress, sizeof(*socketAddress)) == -1) {
		throw SocketException{fd, "connect failed"};
	}
	socklen_t sockpeerLen{sizeof(*socketAddress)};
	if (getsockname(fd, (sockaddr*)socketAddress, &sockpeerLen) == -1) {
		throw SocketException{fd, "getsockname failed"};
	}
}

void bindListenOnSocket(int fd, sockaddr_in* socketAddress) {
	if (bind(fd, (sockaddr*)socketAddress, sizeof(*socketAddress)) == -1) {
		throw SocketException{fd, "bind failed"};
	}
	if (listen(fd, 100) == -1) {
		throw SocketException{fd, "listen failed"};
	}
}

SocketFD acceptOnSocket(int fd) {
	int fdc = accept(fd, nullptr, nullptr);
	if (fdc == -1) {
		throw SocketException{fd, "accept failed"};
	}
	return createSocketFD(fdc);
}

void writeMessage(int fd, char msg) {
	int ret = write(fd, &msg, 1);
	if (ret <= 0) {
		throw SocketException{fd, fmt::format("write returned {:d}", ret)};
	}
}

} // namespace detail
