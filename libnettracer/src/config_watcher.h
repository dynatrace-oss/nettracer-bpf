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

#include "inotify_watcher.h"

#include <filesystem>
#include <functional>
#include <string>

class config_watcher {
public:
    config_watcher() = default;
    ~config_watcher() = default;
	config_watcher(const config_watcher&) = delete;
	config_watcher& operator=(const config_watcher&) = delete;

    void init(const std::filesystem::path file_path);

    operator bool();
    int get_poll_fd();

    void on_pollin();

    bool is_config_changed();

    void reset();

protected:
    void on_event(inotify_event& ie);

    bool config_changed{false};
    inotify_watcher iw{};
    inotify_watcher::watch_token iw_token{};
    std::filesystem::path dir_path{};
    std::filesystem::path file_name{};
};
