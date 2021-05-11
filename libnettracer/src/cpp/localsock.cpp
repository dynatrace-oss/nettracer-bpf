#include "localsock.h"

#include "bpf_generic/log.h"

#include <fmt/core.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

const char msgContinue = 'c';
const char msgBreak = 'b';
const char msgExit = 'x';

bool listenForConnections(std::promise<bool> startPromise) {
	using namespace detail;

	LOG_DEBUG("Starting server");
	SocketFD fd{nullptr, nullptr};
	try {
		fd = createSocket();
		setsockoptReuseaddr(*fd);
		auto socketAddress{createSocketAddress(*fd)};
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

	auto temporaryServerReturn = std::async(std::launch::async, listenForConnections, std::move(startPromise));

	const auto timeout = std::chrono::seconds(10);
	auto waitStatus = startSuccessful.wait_for(timeout);
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
		detail::connectSendClose(msgExit);
	}
	catch (const SocketException& ex) {
		LOG_ERROR(ex.what());
		return false;
	}
	const auto timeout = std::chrono::seconds(10);
	auto waitStatus = serverThreadReturn.wait_for(timeout);
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
		auto ret{detail::connectSendKeep(377)}; // "random" number of "messages"
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

namespace detail {

uint16_t connectSendClose(char msg) {
	auto fd{createSocket()};
	setsockoptLinger(*fd);
	auto socketAddress{createSocketAddress(*fd)};
	connectSocket(*fd, &socketAddress);
	writeMessage(*fd, msg);
	// return source port in network order
	return socketAddress.sin_port;
}

std::pair<SocketFD, uint16_t> connectSendKeep(int reps) {
	auto fd{createSocket()};
	setsockoptNodelay(*fd);
	auto socketAddress{createSocketAddress(*fd)};
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

sockaddr_in createSocketAddress(int fd) {
	sockaddr_in socketAddress;
	in_addr addr;
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_port = htons(LocalSock::serverPort);
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
