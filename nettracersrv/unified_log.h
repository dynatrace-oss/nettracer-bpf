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

#include "bpf_generic/src/log.h"
#include "bpf_program/nettracer-bpf.h"
#include <boost/program_options.hpp>

spdlog::level::level_enum  loglevelFromConfig(const boost::program_options::variables_map& vm);
bool setUpLogging(const boost::program_options::variables_map& vm);
spdlog::level::level_enum bpfLogLevelToSpdlogLevel(const bpf_log_level& level);
void unifyBPFLog(const bpf_log_event_t& evt);
