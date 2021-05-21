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

static const char msgContinue = 'c';
static const char msgBreak = 'b';
static const char msgExit = 'x';

SocketException::SocketException(int fd, const std::string& error) :
	std::runtime_error(fmt::format("Failure for socket with fd={:d}: {}, errno: {:d} ({})", fd, error, errno, strerror(errno))) {}

SocketFD createSocketFD(int fd) {
	return SocketFD{new int{fd}, [](int* fd){ close(*fd); delete fd; }};
}

LocalSock::LocalSock() {
	start();
}

LocalSock::~LocalSock() {
	if (serverThread.joinable()) {
		stop();
	}
}

bool LocalSock::startServer() {
	if (serverThread.joinable()) {
		return false;
	}

	serverThread = std::thread{[this](){
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
			exit(-1);
		}

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
					break;
				}
			}
			catch (const SocketException& ex) {
				LOG_ERROR("Server failed to handle an incoming connection");
				LOG_ERROR(ex.what());
				exit(-1);
			}
		}

		return nullptr;
	}};

	return serverThread.joinable();
}

bool LocalSock::stopServer() {
	if (!serverThread.joinable()) {
		return false;
	}

	try {
		detail::connectSendClose(msgExit);
	}
	catch (const SocketException& ex) {
		LOG_ERROR(ex.what());
		return false;
	}
	serverThread.join();
	return true;
}

bool LocalSock::startClient() {
	if (connection) {
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
	if (!connection) {
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
	std::this_thread::sleep_for(std::chrono::milliseconds(1));
	return startClient();
}

bool LocalSock::stop() {
	return stopClient() && stopServer();
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
