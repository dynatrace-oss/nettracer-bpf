#pragma once

#include "bpf_generic/src/log.h"
#include "bpf_program/nettracer-bpf.h"
#include <boost/program_options.hpp>

spdlog::level::level_enum  loglevelFromConfig(const boost::program_options::variables_map& vm);
bool setUpLogging(const boost::program_options::variables_map& vm);
spdlog::level::level_enum bpfLogLevelToSpdlogLevel(const bpf_log_level& level);
void unifyBPFLog(const bpf_log_event_t& evt);
