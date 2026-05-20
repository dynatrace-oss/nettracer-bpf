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

#include "system_calls.h"
#include <optional>
#include <string>

struct utsname;

namespace bpf {

std::optional<int> getKernelVersion(const ISystemCalls& sysCalls);

bool isKernelSupported(int kernelVersion);

std::string kernelVersionToString(int kernelVersion);

// Returns the number of possible CPUs reported by the kernel via
// /sys/devices/system/cpu/possible (the same value libbpf uses for sizing
// per-CPU BPF maps). Returns std::nullopt if the file cannot be read or
// parsed.
std::optional<unsigned> getNumPossibleCpus(const ISystemCalls& sysCalls);

} // namespace bpf
