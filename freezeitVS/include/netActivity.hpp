#pragma once

// 用户态网络活动采样：不依赖内核模块。
// 读 /proc/net/{tcp,tcp6,udp,udp6}，按 uid 汇总接收队列字节数。
// 两次采样之间该值变大，说明这个 uid 正在收数据（TCP 下载、UDP/QUIC 都覆盖）。
// 只作为 Re:Kernel 网络事件的补充：内核那条路不可用时仍然能识别下载。

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <map>

namespace netActivity {

struct Sample {
    std::map<int, long> rxBytes;  // uid -> 所有 socket 的 rx_queue 之和
};

inline bool parseFile(const char* path, std::map<int, long>& out) {
    FILE* fp = ::fopen(path, "re");
    if (fp == nullptr) return false;

    char line[512];
    // 跳过表头
    if (::fgets(line, sizeof(line), fp) == nullptr) {
        ::fclose(fp);
        return false;
    }

    while (::fgets(line, sizeof(line), fp) != nullptr) {
        // sl local rem st tx_queue:rx_queue tr:tm retrnsmt uid timeout inode
        char* fields[12] = {};
        int n = 0;
        char* p = line;
        while (n < 12 && p != nullptr) {
            fields[n++] = p;
            char* sp = ::strchr(p, ' ');
            if (sp != nullptr) {
                *sp = 0;
                p = sp + 1;
                while (*p == ' ') p++;
            } else {
                p = nullptr;
            }
        }
        if (n < 8) continue;

        const char* queue = fields[4];
        const char* colon = ::strchr(queue, ':');
        if (colon == nullptr) continue;
        const long rx = ::strtol(colon + 1, nullptr, 16);
        const int uid = ::atoi(fields[7]);
        if (uid < 10000) continue;

        out[uid] += rx;
    }

    ::fclose(fp);
    return true;
}

inline bool snapshot(std::map<int, long>& out) {
    out.clear();
    bool ok = false;
    ok |= parseFile("/proc/net/tcp", out);
    ok |= parseFile("/proc/net/tcp6", out);
    ok |= parseFile("/proc/net/udp", out);
    ok |= parseFile("/proc/net/udp6", out);
    return ok;
}

} // namespace netActivity
