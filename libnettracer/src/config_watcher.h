#pragma once

#include "inotify_watcher.h"

#include <boost/noncopyable.hpp>
#include <filesystem>
#include <functional>
#include <string>

class config_watcher : private boost::noncopyable {
public:
    config_watcher() = default;
    ~config_watcher() = default;

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
