#pragma once

#include <stdexcept>
#include <string>

class InsufficientCapabilitiesError : public std::runtime_error {
public:
    InsufficientCapabilitiesError(const std::string& msg)
        : std::runtime_error(msg) {}
};
