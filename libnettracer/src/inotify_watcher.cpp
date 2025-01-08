#include "inotify_watcher.h"

#include <system_error>
#include <unistd.h>
#include <utility>

inotify_watcher::inotify_watcher() {
    fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd == -1) {
        throw std::system_error(errno, std::system_category(), "inotify_init failed");
    }
}

inotify_watcher::~inotify_watcher() {
    for (auto& wd : wds) {
        unwatch_path({wd.first});
    }
    ::close(fd);
}

inotify_watcher::watch_token inotify_watcher::watch_path(std::string path, uint32_t inotify_mask, watch_callback wc) {
    if (fd == -1) {
        return {-1};
    }
    int wd = ::inotify_add_watch(fd, path.c_str(), inotify_mask);
    if (wd == -1) {
        return {-1};
    }
    wds.insert(std::make_pair(wd, wc));
    return {wd};
}

bool inotify_watcher::unwatch_path(watch_token token) {
    if (!token) {
        return false;
    }
    if (fd == -1) {
        return false;
    }
    if (wds.find(token.wd) == wds.end()) {
        return false;
    }
    int rc = ::inotify_rm_watch(fd, token.wd);
    if (rc == -1) {
        return false;
    }
    wds.erase(token.wd);
    return true;
}

inotify_watcher::operator bool() {
    return fd != -1;
}

int inotify_watcher::get_poll_fd() {
    return fd;
}

void inotify_watcher::on_pollin() {
    inotify_event events[64];
    while (true) {
        auto len = ::read(fd, &events, sizeof(events));
        if (len == -1) {
            break;
        }
        dispatch(events, len / sizeof(*events));
    }
}

void inotify_watcher::dispatch(inotify_event* events, size_t count) {
    while (count) {
        auto wd = wds.find(events->wd);
        if (wd != wds.end()) {
            wd->second(*events);
        }

        ++events;
        --count;
    }
}
