#pragma once

#include "system_calls.h"
#include <optional>
#include <string>

struct utsname;

namespace bpf {

std::optional<int> getKernelVersion(const ISystemCalls& sysCalls);

bool isKernelSupported(int kernelVersion);

std::string kernelVersionToString(int kernelVersion);

} // namespace bpf
