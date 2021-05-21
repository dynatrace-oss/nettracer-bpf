#pragma once

#include <cstdint>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>

// client for guessing offsets specific to IPv6
class ClientSock6 {
public:
    bool readLocalInterface();
    bool setRemoteServerAndPort();
    bool setRemoteServerAndPort(const std::string& serverIp, uint16_t tcpPort);
    bool pokeRemoteServerAndPort();
    bool getDAddress(uint32_t* daddress) const;

private:
	addrinfo remoteServerInfo;
    std::string localInterface;
};
