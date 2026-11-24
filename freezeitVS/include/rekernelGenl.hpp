#pragma once

// Re:Kernel 11+ 的 Generic Netlink 客户端。
// 新版内核模块默认不再创建 /proc/rekernel，改为按 family 名字 "rekernel" 解析，
// 事件通过 mcgrp "events" 组播下发，payload 仍是旧的 "key=value,...;" 字符串。
// 解析出 family id / group id 失败时由调用方回落到旧的 raw netlink 路径。

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <deque>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

namespace rekernelGenl {

static constexpr const char* FAMILY_NAME = "rekernel";
static constexpr const char* GROUP_NAME = "events";
static constexpr int CMD_EVENT = 1;           // REKERNEL_C_EVENT
static constexpr int CMD_ADD_MONITOR_NET = 2; // REKERNEL_C_ADD_MONITOR_NET
static constexpr int CMD_DEL_MONITOR_NET = 3; // REKERNEL_C_DEL_MONITOR_NET
static constexpr int ATTR_MSG = 1;            // REKERNEL_A_MSG
static constexpr int ATTR_UID = 2;            // REKERNEL_A_UID
static constexpr int CMD_GET_VERSION = 4;     // REKERNEL_C_GET_VERSION

inline int nlaAlign(int len) { return (len + 3) & ~3; }

struct Attr {
    uint16_t type;
    uint16_t len;
    const char* data;
};

// 遍历一段 nla 序列
class AttrIter {
public:
    AttrIter(const char* p, int len) : ptr(p), remain(len) {}

    bool next(Attr& out) {
        if (remain < (int) sizeof(struct nlattr)) return false;
        const auto* a = reinterpret_cast<const struct nlattr*>(ptr);
        if (a->nla_len < sizeof(struct nlattr) || a->nla_len > remain) return false;
        out.type = a->nla_type & NLA_TYPE_MASK;
        out.len = a->nla_len - sizeof(struct nlattr);
        out.data = ptr + sizeof(struct nlattr);
        const int step = nlaAlign(a->nla_len);
        ptr += step;
        remain -= step;
        return true;
    }

private:
    const char* ptr;
    int remain;
};

class Client {
public:
    int fd = -1;
    uint16_t familyId = 0;
    uint32_t groupId = 0;
    uint32_t seq = 0;
    // 等 ACK / 查版本时顺带收到的事件先存这里，避免被吃掉
    std::deque<std::string> pendingEvents;

    ~Client() { close(); }

    void close() {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
        familyId = 0;
        groupId = 0;
        pendingEvents.clear();
    }

    // 返回 false: 内核模块不存在 / 不是 genl 版本 / 解析失败
    bool open() {
        close();

        fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
        if (fd < 0) return false;

        struct sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        local.nl_pid = static_cast<uint32_t>(::getpid());
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) != 0) {
            close();
            return false;
        }

        struct timeval tv{};
        tv.tv_sec = 2;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (!resolveFamily()) {
            close();
            return false;
        }

        // 长时间等待事件
        tv.tv_sec = 30;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (groupId == 0) {
            // family 在但没有 "events" 组播组：不是冻它认识的版本，交给旧协议判断
            close();
            return false;
        }

        const int grp = static_cast<int>(groupId);
        if (::setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &grp, sizeof(grp)) != 0) {
            close();
            return false;
        }
        return true;
    }

    // 订阅/取消某个 UID 的入站网络包事件，返回内核错误码（0 成功）
    bool addMonitorNet(uint32_t uid, int* kernelError = nullptr) {
        return sendUidCommand(CMD_ADD_MONITOR_NET, uid, kernelError);
    }

    bool delMonitorNet(uint32_t uid, int* kernelError = nullptr) {
        return sendUidCommand(CMD_DEL_MONITOR_NET, uid, kernelError);
    }

    // 查询内核模块版本（字符串）
    bool queryVersion(char* out, int outLen) {
        if (fd < 0 || familyId == 0) return false;

        char req[128];
        ::memset(req, 0, sizeof(req));
        auto* nlh = reinterpret_cast<struct nlmsghdr*>(req);
        nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
        nlh->nlmsg_type = familyId;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = ++seq;

        auto* gh = reinterpret_cast<struct genlmsghdr*>(NLMSG_DATA(nlh));
        gh->cmd = static_cast<uint8_t>(CMD_GET_VERSION);
        gh->version = 1;

        struct sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        if (::sendto(fd, req, nlh->nlmsg_len, 0,
                     reinterpret_cast<struct sockaddr*>(&kernel), sizeof(kernel)) <= 0)
            return false;

        char buf[2048];
        for (int attempt = 0; attempt < 4; ++attempt) {
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) return false;

            int remain = static_cast<int>(n);
            const char* p = buf;
            while (remain >= static_cast<int>(sizeof(struct nlmsghdr))) {
                const auto* rh = reinterpret_cast<const struct nlmsghdr*>(p);
                if (rh->nlmsg_len < sizeof(struct nlmsghdr) || rh->nlmsg_len > static_cast<unsigned>(remain))
                    break;

                if (rh->nlmsg_type == familyId) {
                    // 可能是版本回复，也可能是事件；事件先入队
                    std::string ev;
                    if (takeEvent(rh, ev)) {
                        pendingEvents.push_back(ev);
                    } else if (rh->nlmsg_len >= sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr)) {
                        const auto* rgh = reinterpret_cast<const struct genlmsghdr*>(NLMSG_DATA(rh));
                        const char* attrs = reinterpret_cast<const char*>(rgh) + GENL_HDRLEN;
                        const int attrsLen = static_cast<int>(rh->nlmsg_len) - NLMSG_HDRLEN - GENL_HDRLEN;
                        AttrIter it(attrs, attrsLen);
                        Attr a{};
                        while (it.next(a)) {
                            if (a.type != ATTR_MSG || a.len <= 0) continue;
                            int copy = a.len;
                            if (copy >= outLen) copy = outLen - 1;
                            ::memcpy(out, a.data, copy);
                            out[copy] = 0;
                            return true;
                        }
                    }
                }

                const int step = NLMSG_ALIGN(rh->nlmsg_len);
                p += step;
                remain -= step;
            }
        }
        return false;
    }

    // >0: 收到一条事件（NUL 结尾的字符串）
    //  0: 超时
    // <0: 出错，需要重连
    int recvEvent(char* out, int outLen) {
        if (!pendingEvents.empty()) {
            const std::string& ev = pendingEvents.front();
            int copy = static_cast<int>(ev.size());
            if (copy >= outLen) copy = outLen - 1;
            if (copy < 0) copy = 0;
            ::memcpy(out, ev.data(), copy);
            out[copy] = 0;
            pendingEvents.pop_front();
            return copy + 1;
        }

        char buf[2048];
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
            return -1;
        }
        if (n == 0) return -1;

        int remain = static_cast<int>(n);
        const char* p = buf;
        while (remain >= static_cast<int>(sizeof(struct nlmsghdr))) {
            const auto* nlh = reinterpret_cast<const struct nlmsghdr*>(p);
            if (nlh->nlmsg_len < sizeof(struct nlmsghdr) || nlh->nlmsg_len > static_cast<unsigned>(remain))
                break;

            if (nlh->nlmsg_type != NLMSG_ERROR && nlh->nlmsg_type != NLMSG_DONE &&
                nlh->nlmsg_len >= sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr)) {
                const auto* gh = reinterpret_cast<const struct genlmsghdr*>(NLMSG_DATA(nlh));
                if (gh->cmd == CMD_EVENT) {
                    const char* attrs = reinterpret_cast<const char*>(gh) + GENL_HDRLEN;
                    const int attrsLen = static_cast<int>(nlh->nlmsg_len) - NLMSG_HDRLEN - GENL_HDRLEN;
                    AttrIter it(attrs, attrsLen);
                    Attr a{};
                    while (it.next(a)) {
                        if (a.type != ATTR_MSG) continue;
                        int copy = a.len;
                        if (copy >= outLen) copy = outLen - 1;
                        if (copy < 0) copy = 0;
                        ::memcpy(out, a.data, copy);
                        out[copy] = 0;
                        return copy + 1;
                    }
                }
            }

            const int step = NLMSG_ALIGN(nlh->nlmsg_len);
            p += step;
            remain -= step;
        }
        return 0;
    }

private:
    // 如果是 EVENT 消息，把 A_MSG 文本取出
    bool takeEvent(const struct nlmsghdr* nlh, std::string& out) const {
        if (nlh->nlmsg_type != familyId) return false;
        if (nlh->nlmsg_len < sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr)) return false;
        const auto* gh = reinterpret_cast<const struct genlmsghdr*>(NLMSG_DATA(nlh));
        if (gh->cmd != CMD_EVENT) return false;

        const char* attrs = reinterpret_cast<const char*>(gh) + GENL_HDRLEN;
        const int attrsLen = static_cast<int>(nlh->nlmsg_len) - NLMSG_HDRLEN - GENL_HDRLEN;
        AttrIter it(attrs, attrsLen);
        Attr a{};
        while (it.next(a)) {
            if (a.type != ATTR_MSG || a.len <= 0) continue;
            out.assign(a.data, a.len);
            return true;
        }
        return false;
    }

    bool sendUidCommand(int cmd, uint32_t uid, int* kernelError) {
        if (fd < 0 || familyId == 0) return false;
        if (kernelError != nullptr) *kernelError = 0;

        char req[256];
        ::memset(req, 0, sizeof(req));

        auto* nlh = reinterpret_cast<struct nlmsghdr*>(req);
        nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
        nlh->nlmsg_type = familyId;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        nlh->nlmsg_seq = ++seq;

        auto* gh = reinterpret_cast<struct genlmsghdr*>(NLMSG_DATA(nlh));
        gh->cmd = static_cast<uint8_t>(cmd);
        gh->version = 1;

        auto* a = reinterpret_cast<struct nlattr*>(req + nlh->nlmsg_len);
        a->nla_type = ATTR_UID;
        a->nla_len = static_cast<uint16_t>(sizeof(struct nlattr) + sizeof(uint32_t));
        ::memcpy(reinterpret_cast<char*>(a) + sizeof(struct nlattr), &uid, sizeof(uint32_t));
        nlh->nlmsg_len += NLA_ALIGN(a->nla_len);

        struct sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        if (::sendto(fd, req, nlh->nlmsg_len, 0,
                     reinterpret_cast<struct sockaddr*>(&kernel), sizeof(kernel)) <= 0)
            return false;

        const int err = waitAck(nlh->nlmsg_seq);
        if (kernelError != nullptr) *kernelError = err;
        return err == 0;
    }

    // 等内核 ACK（同 seq 的 NLMSG_ERROR），返回内核错误码；超时返回 -1
    int waitAck(uint32_t seqNo) {
        char buf[1024];
        for (int i = 0; i < 8; ++i) {
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) return -1;

            int remain = static_cast<int>(n);
            const char* p = buf;
            while (remain >= static_cast<int>(sizeof(struct nlmsghdr))) {
                const auto* h = reinterpret_cast<const struct nlmsghdr*>(p);
                if (h->nlmsg_len < sizeof(struct nlmsghdr) || h->nlmsg_len > static_cast<unsigned>(remain))
                    break;
                if (h->nlmsg_seq == seqNo && h->nlmsg_type == NLMSG_ERROR) {
                    const auto* e = reinterpret_cast<const struct nlmsgerr*>(NLMSG_DATA(h));
                    return e->error;
                }
                if (h->nlmsg_type == familyId) {
                    std::string ev;
                    if (takeEvent(h, ev)) pendingEvents.push_back(ev);
                }
                const int step = NLMSG_ALIGN(h->nlmsg_len);
                p += step;
                remain -= step;
            }
        }
        return -1;
    }

    bool resolveFamily() {
        char req[512];
        ::memset(req, 0, sizeof(req));

        auto* nlh = reinterpret_cast<struct nlmsghdr*>(req);
        nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
        nlh->nlmsg_type = GENL_ID_CTRL;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = ++seq;

        auto* gh = reinterpret_cast<struct genlmsghdr*>(NLMSG_DATA(nlh));
        gh->cmd = CTRL_CMD_GETFAMILY;
        gh->version = 1;

        const int nameLen = static_cast<int>(::strlen(FAMILY_NAME)) + 1;
        auto* a = reinterpret_cast<struct nlattr*>(req + nlh->nlmsg_len);
        a->nla_type = CTRL_ATTR_FAMILY_NAME;
        a->nla_len = static_cast<uint16_t>(sizeof(struct nlattr) + nameLen);
        ::memcpy(reinterpret_cast<char*>(a) + sizeof(struct nlattr), FAMILY_NAME, nameLen);
        nlh->nlmsg_len += nlaAlign(a->nla_len);

        struct sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        if (::sendto(fd, req, nlh->nlmsg_len, 0,
                     reinterpret_cast<struct sockaddr*>(&kernel), sizeof(kernel)) < 0)
            return false;

        char resp[4096];
        const ssize_t n = ::recv(fd, resp, sizeof(resp), 0);
        if (n <= 0) return false;

        int remain = static_cast<int>(n);
        const char* p = resp;
        while (remain >= static_cast<int>(sizeof(struct nlmsghdr))) {
            const auto* rh = reinterpret_cast<const struct nlmsghdr*>(p);
            if (rh->nlmsg_len < sizeof(struct nlmsghdr) || rh->nlmsg_len > static_cast<unsigned>(remain))
                return false;

            if (rh->nlmsg_type == GENL_ID_CTRL &&
                rh->nlmsg_len >= sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr)) {
                const auto* rgh = reinterpret_cast<const struct genlmsghdr*>(NLMSG_DATA(rh));
                if (rgh->cmd == CTRL_CMD_NEWFAMILY) {
                    const char* attrs = reinterpret_cast<const char*>(rgh) + GENL_HDRLEN;
                    const int attrsLen = static_cast<int>(rh->nlmsg_len) - NLMSG_HDRLEN - GENL_HDRLEN;
                    AttrIter it(attrs, attrsLen);
                    Attr at{};
                    while (it.next(at)) {
                        if (at.type == CTRL_ATTR_FAMILY_ID && at.len >= 2) {
                            ::memcpy(&familyId, at.data, 2);
                        } else if (at.type == CTRL_ATTR_MCAST_GROUPS) {
                            parseGroups(at.data, at.len);
                        }
                    }
                    return familyId != 0;
                }
            }

            const int step = NLMSG_ALIGN(rh->nlmsg_len);
            p += step;
            remain -= step;
        }
        return false;
    }

    void parseGroups(const char* data, int len) {
        AttrIter groups(data, len);
        Attr g{};
        while (groups.next(g)) {
            AttrIter fields(g.data, g.len);
            Attr f{};
            const char* name = nullptr;
            uint32_t id = 0;
            while (fields.next(f)) {
                if (f.type == CTRL_ATTR_MCAST_GRP_NAME && f.len > 0) {
                    name = f.data;
                } else if (f.type == CTRL_ATTR_MCAST_GRP_ID && f.len >= 4) {
                    ::memcpy(&id, f.data, 4);
                }
            }
            if (name != nullptr && ::strcmp(name, GROUP_NAME) == 0) {
                groupId = id;
                return;
            }
        }
    }
};

} // namespace rekernelGenl
