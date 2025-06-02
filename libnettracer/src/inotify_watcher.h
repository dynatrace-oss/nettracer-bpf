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

#include <functional>
#include <map>
#include <string>
#include <sys/inotify.h>

class inotify_watcher {
public:
    using watch_callback = std::function<void(inotify_event&)>;

    struct watch_token {
        operator bool() { return wd != -1; };
        int wd{-1};
    };

    inotify_watcher();
    ~inotify_watcher();

    watch_token watch_path(std::string path, uint32_t inotify_mask, watch_callback wc);
    bool unwatch_path(watch_token token);

    operator bool();
    int get_poll_fd();

    void on_pollin();

protected:
    void dispatch(inotify_event* events, size_t count);

    // inotify fd
    int fd{-1};

    // inotify watch descriptors
    std::map<int, watch_callback> wds;
};
