#include "localsock6.h"
#include "bpf_generic/src/log.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <netinet/in.h>
#include <regex>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>


// implementation of test client for ipv6 //

static const char* printIpAddr(const sockaddr_in6* addr){
	static char buffer[INET6_ADDRSTRLEN] = {0};
	return inet_ntop(AF_INET6, &(addr->sin6_addr), buffer, sizeof(buffer));
}

bool ClientSock6::setRemoteServerAndPort(){
    std::string randomAddress("fe80::4173:69ff:fe61:2106");
    uint16_t randomPort = htons(0x2019U);
    return setRemoteServerAndPort(randomAddress, randomPort);
}
bool ClientSock6::setRemoteServerAndPort(const std::string& serverIp, uint16_t tcpPort){
	addrinfo hints = { 0 };
	addrinfo *res = nullptr;

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	std::string ipv6AddressOnEthIfc = serverIp + "%" + localInterface;
	int gai_err = getaddrinfo(ipv6AddressOnEthIfc.c_str(), "554", &hints, &res);

	if (gai_err)	{
		LOG_ERROR("getaddrinfo: {:s}", gai_strerror(gai_err));
		return false;
	}
	remoteServerInfo = *res;
	sockaddr_in6* addr = (sockaddr_in6*)(remoteServerInfo.ai_addr);

	LOG_DEBUG("RemoteAddressInfo addr={:s}", printIpAddr(addr));
	return true;
}

bool ClientSock6::getDAddress(uint32_t* daddress) const {
	if (remoteServerInfo.ai_family == AF_INET6 && remoteServerInfo.ai_addr != nullptr) {
		sockaddr_in6* addr = (sockaddr_in6*)(remoteServerInfo.ai_addr);
		daddress[0] = addr->sin6_addr.s6_addr32[0];
		daddress[1] = addr->sin6_addr.s6_addr32[1];
		daddress[2] = addr->sin6_addr.s6_addr32[2];
		daddress[3] = addr->sin6_addr.s6_addr32[3];
		return true;
	}
	return false;
}

bool ClientSock6::readLocalInterface() {
/* format of /proc/net/if_inet6 file entries
fe8000000000000002155dfffe67f8d5 05 40 20 80 eth0
00000000000000000000000000000001 01 80 10 80 lo
+------------------------------+ ++ ++ ++ ++ ++
|                                |  |  |  |  |
1                                2  3  4  5  6
1. IPv6 address displayed in 32 hexadecimal chars without colons as separator
2. Netlink device number (interface index) in hexadecimal (see ”ip addr” , too)
3. Prefix length in hexadecimal
4. Scope value:
	IPV6_ADDR_GLOBAL        0x0000U
	IPV6_ADDR_LOOPBACK      0x0010U
	IPV6_ADDR_LINKLOCAL     0x0020U
	IPV6_ADDR_SITELOCAL     0x0040U
	IPV6_ADDR_COMPATv4      0x0080U
5. Interface flags (see ”include/linux/rtnetlink.h” and ”net/ipv6/addrconf.c” for more)
6. Device name
*/
    auto readWholeFile = [](const std::string &pathName)->std::string {
		std::ifstream inputFile;
		inputFile.open(pathName);      // open input file
        char buffer[4048] = {};
        if ( inputFile.good()){
		    inputFile.read(buffer, sizeof(buffer));       // read the whole file into the buffer
		    inputFile.close();                    // close file handle
        }
		return std::string(buffer);
    };
    std::string text = readWholeFile( "/proc/net/if_inet6");
    if ( text.empty() ) {
        LOG_ERROR("ClientSock6: Failed to get local ipv6 interface: failed to read /proc/net/if_inet6 file");
        return false;
    }
    std::istringstream input(text);
    std::regex re(R"(^([[:xdigit:]]+)\s+([[:xdigit:]]+)\s+([[:xdigit:]]+)\s+([[:xdigit:]]+)\s+([[:xdigit:]]+)\s+(.*)$)");
    for (std::string line; std::getline(input, line); ) {
        std::smatch partsMatch;
        if ( std::regex_match(line, partsMatch, re)){
            if ( partsMatch[1].str().substr(0,4) == "fe80") {
                localInterface = partsMatch[6].str();
                LOG_DEBUG("ClientSock6: found local interface line:{:s} interface:{:s}", line, localInterface);
                return true;
            } else {
                LOG_TRACE("ignored line:{:s}", line);
            }

        } else {
            // wrong line
            LOG_DEBUG("failed line:{:s}", line);
        }
    }
	LOG_ERROR("Failed to find local interface");
    return false;
}

bool ClientSock6::pokeRemoteServerAndPort() {
	int fd = socket(remoteServerInfo.ai_family, remoteServerInfo.ai_socktype,remoteServerInfo.ai_protocol);
	if (fd < 0) {
		LOG_TRACE("socket creation failed errno:{}", errno);
		return false;
	}
	int arg  = 0;
  	// Set non-blocking
	if ((arg = fcntl(fd, F_GETFL, NULL)) < 0) {
		LOG_TRACE("Error fcntl(..., F_GETFL) {:s}", strerror(errno));
  	} else {
  		arg |= O_NONBLOCK;
		if (fcntl(fd, F_SETFL, arg) < 0) {
     		LOG_TRACE("Error fcntl(..., F_SETFL) {:s}", strerror(errno));
		}
	}
	if (connect(fd, remoteServerInfo.ai_addr, remoteServerInfo.ai_addrlen) < 0) {
		LOG_TRACE("connect failed as expected err:{}", errno);
		close(fd);
	    return false;
	} else {
		//LOG_INFO("connect to {}:{} OK", *(remoteServerInfo.ai_addr), remoteServerInfo.ai_addrlen );
		LOG_TRACE("connect OK");
		close(fd);
		return true;
	}
}
