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
