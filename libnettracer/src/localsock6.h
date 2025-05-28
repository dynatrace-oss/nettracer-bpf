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

#include <cstdint>
#include <netdb.h>
#include <string>

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
