#include "config_watcher.h"

#include <filesystem>
#include <functional>
#include <stdexcept>
#include <system_error>

using namespace std::literals::string_literals;

void config_watcher::init(const std::filesystem::path file_path) {
    if (iw_token) {
        throw std::logic_error("config_watcher already initialized");
    }
    if (file_path.empty()) {
        return;
    }

    dir_path = file_path.parent_path();
    file_name = file_path.filename();
    iw_token = iw.watch_path(dir_path, IN_MOVED_TO, std::bind(&config_watcher::on_event, this, std::placeholders::_1));
    if (!iw_token) {
        throw std::system_error(errno, std::system_category(), dir_path.c_str());
    }
}

config_watcher::operator bool() {
    return iw_token;
}

int config_watcher::get_poll_fd() {
    return iw.get_poll_fd();
}

void config_watcher::on_pollin() {
    if (!iw_token) {
        return;
    }
    iw.on_pollin();
}

void config_watcher::on_event(inotify_event& ie) {
    if (!(ie.mask & IN_MOVED_TO)) {
        return;
    }
    if (!ie.len) {
        return;
    }
    if (ie.wd != iw_token.wd) {
        return;
    }
    if (file_name != ie.name) {
        return;
    }

    config_changed = true;
}

bool config_watcher::is_config_changed() {
    return config_changed;
}

void config_watcher::reset() {
    config_changed = false;
}
