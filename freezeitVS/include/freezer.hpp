#pragma once

#include "utils.hpp"
#include "vpopen.hpp"
#include "managedApp.hpp"
#include "doze.hpp"
#include "freezeit.hpp"
#include "systemTools.hpp"
#include "rekernelGenl.hpp"
#include <linux/netlink.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#define PACKET_SIZE      128
//#define NETLINK_TEST     26
#define NETLINK_TEST     22  // 需要读取 /proc/rekernel/
#define USER_PORT        100
#define MAX_PLOAD        125
#define MSG_LEN          125

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    char  msg[MSG_LEN];
} user_msg_info;

class Freezer {
private:
    Freezeit& freezeit;
    ManagedApp& managedApp;
    SystemTools& systemTools;
    Settings& settings;
    Doze& doze;

    vector<thread> threads;

    WORK_MODE workMode = WORK_MODE::GLOBAL_SIGSTOP;
    map<int, int> pendingHandleList;     //挂起列队 无论黑白名单 { uid, timeRemain:sec }
    set<int> lastForegroundApp;          //前台应用
    set<int> curForegroundApp;           //新前台应用
    set<int> curFgBackup;                //新前台应用备份 用于进入doze前备份， 退出后恢复
    set<int> naughtyApp;                 //冻结期间存在异常解冻或唤醒进程的应用
    mutex naughtyMutex;

    uint32_t timelineIdx = 0;
    uint32_t unfrozenTimeline[4096] = {};

    bool isReKernelConnected = false;
    int binderEventCnt = 0;

    // Re:Kernel 网络事件（入站数据包）相关
    set<int> netMonitored;              // 已向内核订阅网络事件的 UID
    map<int, long> lastNetEvent;        // uid -> 最近一次有效入站 TCP 数据时间
    map<int, long> lastNetLog;          // 日志节流
    map<int, long> lastNetUnfreeze;     // 解冻节流：连续事件不重复扫 /proc
    struct ZeroWin { long start = 0; int cnt = 0; };
    map<int, ZeroWin> netZeroWin;       // uid -> 零长度入向包窗口（疑似上传时的对端 ACK）
    struct RateWin { long start = 0; int cnt = 0; };
    map<int, RateWin> netRateWin;       // uid -> TCP 大包短窗口计数
    map<int, RateWin> netRateWinUdp;    // uid -> UDP 包短窗口计数（阈值更低）
    map<int, long> lastNetTrigger;      // uid -> 上次触发（同一秒只处理一次）
    map<int, long> lastBinderWake;      // uid -> 上次 Binder 解冻，做冷却
    set<int> netSeenUid;                // 首次命中有效事件时打一条日志
    set<int> netOutSeen;                // 首次命中“疑似上传”时打一条日志
    set<int> netZeroSeen;               // 首次收到零长度事件时打一条日志（判断通道是否通）
    long lastNetSummary = 0;            // 订阅摘要日志节流
    uint32_t netAppliedTcp = 0;         // 已下发到内核的 TCP 阈值（0=内核默认）
    uint32_t netAppliedUdp = 0;         // 已下发到内核的 UDP 阈值（0=内核默认）
    static constexpr int NET_SYNC_SEC = 5;   // 每 5 秒核对一次订阅（应用可能刚启动/刚改配置）
    uint64_t netEventCnt = 0;           // 命中有效活动（入向大数据/疑似上传）的次数
    uint64_t netIgnoredZero = 0;        // data_len=0（握手/纯 ACK）事件数
    uint64_t netTcpSeen = 0;            // 收到的 TCP 网络事件（data_len>0）
    uint64_t netUdpSeen = 0;            // 收到的 UDP 网络事件（data_len>0）
    set<int> netUdpSeenUid;             // 首次收到某 UID 的 UDP 事件时打一条日志
    static constexpr int NET_IDLE_SEC = 5;  // 最近这么久内有网络包就不冻结

    // data_len 是单个 skb 的瞬时值，不做时间累积。正常下载的报文基本都是
    // 1404/1440 的整 MSS（GRO 后是 2808、4212 的倍数），推送给付通常几百字节。
    // TCP：保持原策略。QQ 这类 ~1.5KB 的推送 20-30 秒才一个，
    // 进不了速率窗口，不会重置倒计时。
    static constexpr int NET_EVENT_MIN_BYTES = 1024; // TCP 参与速率统计的最小包
    static constexpr int NET_BIG_EVENT_BYTES = 4096; // TCP 单包 >=4KB（GRO 合并）直接算
    // UDP：视频/语音是私有 RTC 协议，单包普遍 600~1200B，阈值单独调低。
    static constexpr int NET_UDP_MIN_BYTES = 512;    // UDP 参与速率统计的最小包
    static constexpr int NET_UDP_BIG_EVENT_BYTES = 2048; // UDP 单包 >=2KB 直接算
    static constexpr int NET_BURST_WINDOW_SEC = 3;   // 或 3 秒内 >=4 个达标包
    static constexpr int NET_BURST_MIN_EVENTS = 4;
    static constexpr int BINDER_WAKE_COOLDOWN_SEC = 60; // 同一 UID 的 Binder 解冻冷却
    // Re:Kernel 只上报入方向（LOCAL_IN）。出方向没有字节数可用，只能间接看：
    // 上传时对端会持续回 ACK，这些是 data_len=0 的入向包。10 秒内 >=48 个
    // 零长度包，约等于对端确认了 64KB 上传，此时也重置倒计时。
    static constexpr int NET_ZERO_WINDOW_SEC = 10;
    static constexpr int NET_ZERO_ACTIVE_CNT = 48;

    int refreezeSecRemain = 60; //开机 一分钟时 就压一次
    int remainTimesToRefreshTopApp = 2; //允许多线程冲突，不需要原子操作

    static const size_t GET_VISIBLE_BUF_SIZE = 256 * 1024;
    unique_ptr<char[]> getVisibleAppBuff;

    binder_state bs{ -1, nullptr, 128 * 1024ULL };

    const char* cgroupV2FreezerCheckPath = "/sys/fs/cgroup/uid_0/cgroup.freeze";
    const char* cgroupV2frozenCheckPath = "/sys/fs/cgroup/frozen/cgroup.freeze";       // "1" frozen
    const char* cgroupV2unfrozenCheckPath = "/sys/fs/cgroup/unfrozen/cgroup.freeze";   // "0" unfrozen

    const char* cpusetEventPath = "/dev/cpuset/top-app";
    //const char* cpusetEventPathA12 = "/dev/cpuset/top-app/tasks";
    //const char* cpusetEventPathA13 = "/dev/cpuset/top-app/cgroup.procs";

    const char* cgroupV1FrozenPath = "/dev/jark_freezer/frozen/cgroup.procs";
    const char* cgroupV1UnfrozenPath = "/dev/jark_freezer/unfrozen/cgroup.procs";

    // 如果直接使用 uid_xxx/cgroup.freeze 可能导致无法解冻
    const char* cgroupV2UidPidPath = "/sys/fs/cgroup/uid_%d/pid_%d/cgroup.freeze"; // "1"frozen   "0"unfrozen
    const char* cgroupV2FrozenPath = "/sys/fs/cgroup/frozen/cgroup.procs";         // write pid
    const char* cgroupV2UnfrozenPath = "/sys/fs/cgroup/unfrozen/cgroup.procs";     // write pid


    const char v2wchan[16] = "do_freezer_trap";      // FreezerV2冻结状态
    const char v1wchan[16] = "__refrigerator";       // FreezerV1冻结状态
    const char SIGSTOPwchan[16] = "do_signal_stop";  // SIGSTOP冻结状态
    const char v2xwchan[16] = "get_signal";          // FreezerV2冻结状态 内联状态
    const char pStopwchan[16] = "ptrace_stop";       // ptrace冻结状态
    const char epoll_wait1_wchan[16] = "SyS_epoll_wait";
    const char epoll_wait2_wchan[16] = "do_epoll_wait";
    const char binder_wchan[32] = "binder_ioctl_write_read";
    const char pipe_wchan[16] = "pipe_wait";

public:
    Freezer& operator=(Freezer&&) = delete;

    Freezer(Freezeit& freezeit, Settings& settings, ManagedApp& managedApp,
        SystemTools& systemTools, Doze& doze) :
        freezeit(freezeit), managedApp(managedApp), systemTools(systemTools),
        settings(settings), doze(doze) {

        getVisibleAppBuff = make_unique<char[]>(GET_VISIBLE_BUF_SIZE);

        binderInit("/dev/binder");

        threads.emplace_back(thread(&Freezer::cpuSetTriggerTask, this)); //监控前台
        threads.emplace_back(thread(&Freezer::binderEventTriggerTask, this)); //binder事件
        threads.emplace_back(thread(&Freezer::cycleThreadFunc, this));

        checkAndMountV2();
        switch (static_cast<WORK_MODE>(settings.setMode)) {
        case WORK_MODE::V2FROZEN: {
            if (checkFreezerV2FROZEN()) {
                workMode = WORK_MODE::V2FROZEN;
                freezeit.log("Freezer类型已设为 V2(FROZEN)");
                return;
            }
            freezeit.log("不支持自定义Freezer类型 V2(FROZEN)");
        } break;

        case WORK_MODE::V2UID: {
            if (checkFreezerV2UID()) {
                workMode = WORK_MODE::V2UID;
                freezeit.log("Freezer类型已设为 V2(UID)");
                return;
            }
            freezeit.log("不支持自定义Freezer类型 V2(UID)");
        } break;

        case WORK_MODE::GLOBAL_SIGSTOP: {
            workMode = WORK_MODE::GLOBAL_SIGSTOP;
            freezeit.log("已设置[全局SIGSTOP], [Freezer冻结]将变为[SIGSTOP冻结]");
        } return;
        }

        // 以上手动选择若不支持或失败，下面将进行自动选择
        if (checkFreezerV2FROZEN()) {
            workMode = WORK_MODE::V2FROZEN;
            freezeit.log("Freezer类型已设为 V2(FROZEN)");
        }
        else if (checkFreezerV2UID()) {
            workMode = WORK_MODE::V2UID;
            freezeit.log("Freezer类型已设为 V2(UID)");
        }
        else {
            workMode = WORK_MODE::GLOBAL_SIGSTOP;
            freezeit.log("已开启 [全局SIGSTOP] 冻结模式");
        }
    }

    const char* getCurWorkModeStr() {
        switch (workMode)
        {
        case WORK_MODE::V2FROZEN:       return "FreezerV2 (FROZEN)";
        case WORK_MODE::V2UID:          return "FreezerV2 (UID)";
        case WORK_MODE::GLOBAL_SIGSTOP: return "全局SIGSTOP";
        }
        return "未知";
    }

    void getPids(appInfoStruct& appInfo) {
        START_TIME_COUNT;

        appInfo.pids.clear();

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            char errTips[256];
            snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                strerror(errno));
            fprintf(stderr, "%s", errTips);
            freezeit.log(errTips);
            return;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            if (statBuf.st_uid != (uid_t)appInfo.uid) continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256];
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const string& package = appInfo.package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;
            const char endChar = readBuff[package.length()]; // 特例 com.android.chrome_zygote 无法binder冻结
            if (endChar != ':' && endChar != 0)continue;

            appInfo.pids.emplace_back(pid);
        }
        closedir(dir);
        END_TIME_COUNT;
    }

    //临时解冻
    void unFreezerTemporary(set<int>& uids) {
        curForegroundApp.insert(uids.begin(), uids.end());
        updateAppProcess();
    }

    void unFreezerTemporary(int uid) {
        curForegroundApp.insert(uid);
        updateAppProcess();
    }

    map<int, vector<int>> getRunningPids(set<int>& uidSet) {
        START_TIME_COUNT;
        map<int, vector<int>> pids;

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            char errTips[256];
            snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                strerror(errno));
            fprintf(stderr, "%s", errTips);
            freezeit.log(errTips);
            return pids;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            const int uid = statBuf.st_uid;
            if (!uidSet.contains(uid))continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256];
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const string& package = managedApp[uid].package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;
            const char endChar = readBuff[package.length()]; // 特例 com.android.chrome_zygote 无法binder冻结
            if (endChar != ':' && endChar != 0)continue;

            pids[uid].emplace_back(pid);
        }
        closedir(dir);
        END_TIME_COUNT;
        return pids;
    }

    set<int> getRunningUids(set<int>& uidSet) {
        START_TIME_COUNT;
        set<int> uids;

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            char errTips[256];
            snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                strerror(errno));
            fprintf(stderr, "%s", errTips);
            freezeit.log(errTips);
            return uids;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            const int uid = statBuf.st_uid;
            if (!uidSet.contains(uid))continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256];
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const string& package = managedApp[uid].package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;
            const char endChar = readBuff[package.length()]; // 特例 com.android.chrome_zygote 无法binder冻结
            if (endChar != ':' && endChar != 0)continue;

            uids.insert(uid);
        }
        closedir(dir);
        END_TIME_COUNT;
        return uids;
    }

    void handleSignal(const appInfoStruct& appInfo, const int signal) {
        if (signal == SIGKILL) {
            //先暂停 然后再杀，否则有可能会复活
            for (const auto pid : appInfo.pids) {
                freezeit.debugFmt("暂停 [%s:%d]", appInfo.label.c_str(), pid);
                kill(pid, SIGSTOP);
            }

            usleep(1000 * 50);
            for (const auto pid : appInfo.pids) {
                freezeit.debugFmt("终结 [%s:%d]", appInfo.label.c_str(), pid);
                kill(pid, SIGKILL);
            }

            return;
        }

        for (const int pid : appInfo.pids)
            if (kill(pid, signal) < 0 && signal == SIGSTOP)
                freezeit.logFmt("SIGSTOP冻结 [%s:%d] 失败[%s]",
                    appInfo.label.c_str(), pid, strerror(errno));
    }

    void handleFreezer(const appInfoStruct& appInfo, const bool freeze) {
        char path[256];

        switch (workMode) {
        case WORK_MODE::V2FROZEN: {
            for (const int pid : appInfo.pids) {
                if (!Utils::writeInt(freeze ? cgroupV2FrozenPath : cgroupV2UnfrozenPath, pid))
                    freezeit.logFmt("%s [%s PID:%d] 失败(V2FROZEN)",
                        freeze ? "冻结" : "解冻", appInfo.label.c_str(), pid);
            }
        } break;

        case WORK_MODE::V2UID: {
            for (const int pid : appInfo.pids) {
                snprintf(path, sizeof(path), cgroupV2UidPidPath, appInfo.uid, pid);
                if (!Utils::writeString(path, freeze ? "1" : "0", 2))
                    freezeit.logFmt("%s [%s PID:%d] 失败(进程可能已结束或者Freezer控制器尚未初始化PID路径)",
                        freeze ? "冻结" : "解冻", appInfo.label.c_str(), pid);
            }
        } break;

        // 本函数只处理Freezer模式，其他冻结模式不应来到此处
        default: {
            freezeit.logFmt("%s 使用了错误的冻结模式", appInfo.label.c_str());
        } break;
        }
    }

    // < 0 : 冻结binder失败的pid， > 0 : 冻结成功的进程数
    int handleProcess(appInfoStruct& appInfo, const bool freeze) {
        START_TIME_COUNT;

        if (freeze) {
            getPids(appInfo);
        }
        else {
            erase_if(appInfo.pids, [&appInfo](const int pid) {
                char path[32] = {};
                
                //snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
                //return !Utils::readString(path).starts_with(appInfo.package);

                snprintf(path, sizeof(path), "/proc/%d", pid);
                struct stat statBuf {};
                if (stat(path, &statBuf)) return true;
                return (uid_t)appInfo.uid != statBuf.st_uid;
                });
        }

        switch (appInfo.freezeMode) {
        case FREEZE_MODE::FREEZER: 
        case FREEZE_MODE::FREEZER_BREAK: {
            if (workMode != WORK_MODE::GLOBAL_SIGSTOP) {
                const int res = handleBinder(appInfo, freeze);
                if (res < 0 && freeze && appInfo.isPermissive)
                    return res;
                handleFreezer(appInfo, freeze);
                break;
            }
            // 如果是全局 WORK_MODE::GLOBAL_SIGSTOP 则顺着执行下面
        }

        case FREEZE_MODE::SIGNAL:
        case FREEZE_MODE::SIGNAL_BREAK: {
            const int res = handleBinder(appInfo, freeze);
            if (res < 0 && freeze && appInfo.isPermissive)
                return res;
            handleSignal(appInfo, freeze ? SIGSTOP : SIGCONT);
        } break;

        case FREEZE_MODE::TERMINATE: {
            if (freeze)
                handleSignal(appInfo, SIGKILL);
            return 0;
        }

        default: { // 刚刚切到白名单，但仍在 pendingHandleList 时，就会执行到这里
            //freezeit.logFmt("不再冻结此应用：%s %s", appInfo.label.c_str(),
            //    getModeText(appInfo.freezeMode).c_str());
            return 0;
        }
        }

        if (settings.isWakeupEnable()) {
            // 无论冻结还是解冻都要清除 解冻时间线上已设置的uid
            if(0 <= appInfo.timelineUnfrozenIdx && appInfo.timelineUnfrozenIdx < 4096)
                unfrozenTimeline[appInfo.timelineUnfrozenIdx] = 0;

            // 冻结就需要在 解冻时间线 插入下一次解冻的时间
            if (freeze && appInfo.pids.size() && appInfo.isSignalOrFreezer()) {
                int nextIdx = (timelineIdx + settings.getWakeupTimeout()) & 0x0FFF; // [ %4096]
                while (unfrozenTimeline[nextIdx])
                    nextIdx = (nextIdx + 1) & 0x0FFF;
                appInfo.timelineUnfrozenIdx = nextIdx;
                unfrozenTimeline[nextIdx] = appInfo.uid;
            }
            else {
                appInfo.timelineUnfrozenIdx = -1;
            }
        }

        if (freeze && appInfo.needBreakNetwork()) {
            const auto ret = systemTools.breakNetworkByLocalSocket(appInfo.uid);
            switch (static_cast<REPLY>(ret)) {
            case REPLY::SUCCESS:
                freezeit.logFmt("断网成功: %s", appInfo.label.c_str());
                break;
            case REPLY::FAILURE:
                freezeit.logFmt("断网失败: %s", appInfo.label.c_str());
                break;
            default:
                freezeit.logFmt("断网 未知回应[%d] %s", ret, appInfo.label.c_str());
                break;
            }
        }

        END_TIME_COUNT;
        return appInfo.pids.size();
    }


    // 重新压制第三方。 白名单, 前台, 待冻结列队 都跳过
    void checkReFreezeBackup() {
        START_TIME_COUNT;

        if (!settings.isRefreezeEnable()) return;

        if (--refreezeSecRemain > 0) return;
        refreezeSecRemain = settings.getRefreezeTimeout();

        lock_guard<mutex> lock(naughtyMutex);

        if (naughtyApp.size() == 0) {
            DIR* dir = opendir("/proc");
            if (dir == nullptr) {
                char errTips[256];
                snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                    strerror(errno));
                fprintf(stderr, "%s", errTips);
                freezeit.log(errTips);
                return;
            }

            struct dirent* file;
            while ((file = readdir(dir)) != nullptr) {
                if (file->d_type != DT_DIR) continue;
                if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

                const int pid = atoi(file->d_name);
                if (pid <= 100) continue;

                char fullPath[64];
                memcpy(fullPath, "/proc/", 6);
                memcpy(fullPath + 6, file->d_name, 6);

                struct stat statBuf;
                if (stat(fullPath, &statBuf))continue;
                const int uid = statBuf.st_uid;
                if (!managedApp.contains(uid) || pendingHandleList.contains(uid) || curForegroundApp.contains(uid))
                    continue;

                auto& appInfo = managedApp[uid];
                if (appInfo.isWhitelist())
                    continue;

                strcat(fullPath + 8, "/cmdline");
                char readBuff[256];
                if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
                const auto& package = appInfo.package;
                if (strncmp(readBuff, package.c_str(), package.length())) continue;
                const char endChar = readBuff[package.length()]; // 特例 com.android.chrome_zygote 无法binder冻结
                if (endChar != ':' && endChar != 0)continue;

                memcpy(fullPath + 6, file->d_name, 6);
                strcat(fullPath + 8, "/wchan");
                if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
                if (strcmp(readBuff, v2wchan) && strcmp(readBuff, v1wchan) && strcmp(readBuff, SIGSTOPwchan) && 
                    strcmp(readBuff, v2xwchan) && strcmp(readBuff, pStopwchan)) {
                    naughtyApp.insert(uid);
                }
            }
            closedir(dir);
        }

        stackString<1024> tmp("定时压制");
        for (const auto uid : naughtyApp) {
            pendingHandleList[uid] = 1;
            tmp.append(' ').append(managedApp[uid].label.c_str());
        }
        if (naughtyApp.size()) {
            naughtyApp.clear();
            freezeit.log(string_view(tmp.c_str(), tmp.length));
        }
        else {
            freezeit.log("定时压制 目前均处于冻结状态");
        }

        END_TIME_COUNT;
    }


    // 临时解冻：检查已冻结应用的进程状态wchan，若有未冻结进程则临时解冻
    void checkUnFreeze() {
        START_TIME_COUNT;

        if (--refreezeSecRemain > 0) return;
        refreezeSecRemain = 3600;// 固定每小时检查一次

        lock_guard<mutex> lock(naughtyMutex);

        if (naughtyApp.size() == 0) {
            DIR* dir = opendir("/proc");
            if (dir == nullptr) {
                char errTips[256];
                snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                    strerror(errno));
                fprintf(stderr, "%s", errTips);
                freezeit.log(errTips);
                return;
            }

            struct dirent* file;
            while ((file = readdir(dir)) != nullptr) {
                if (file->d_type != DT_DIR) continue;
                if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

                const int pid = atoi(file->d_name);
                if (pid <= 100) continue;

                char fullPath[64];
                memcpy(fullPath, "/proc/", 6);
                memcpy(fullPath + 6, file->d_name, 6);

                struct stat statBuf;
                if (stat(fullPath, &statBuf))continue;
                const int uid = statBuf.st_uid;
                if (!managedApp.contains(uid) || pendingHandleList.contains(uid) || curForegroundApp.contains(uid))
                    continue;

                auto& appInfo = managedApp[uid];
                if (appInfo.isWhitelist())
                    continue;

                strcat(fullPath + 8, "/cmdline");
                char readBuff[256];
                if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
                const auto& package = appInfo.package;
                if (strncmp(readBuff, package.c_str(), package.length())) continue;
                const char endChar = readBuff[package.length()]; // 特例 com.android.chrome_zygote 无法binder冻结
                if (endChar != ':' && endChar != 0)continue;

                memcpy(fullPath + 6, file->d_name, 6);
                strcat(fullPath + 8, "/wchan");
                if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
                if (strcmp(readBuff, v2wchan) && strcmp(readBuff, v1wchan) && strcmp(readBuff, SIGSTOPwchan) &&
                    strcmp(readBuff, v2xwchan) && strcmp(readBuff, pStopwchan)) {
                    naughtyApp.insert(uid);
                }
            }
            closedir(dir);
        }

        if (naughtyApp.size()) {
            stackString<1024> tmp("临时解冻");
            for (const auto uid : naughtyApp) {
                tmp.append(' ').append(managedApp[uid].label.c_str());
            }
            freezeit.log(string_view(tmp.c_str(), tmp.length));
            unFreezerTemporary(naughtyApp);
            naughtyApp.clear();
        }

        END_TIME_COUNT;
    }

    bool mountFreezerV1() {
        if (!access("/dev/jark_freezer", F_OK)) // 已挂载
            return true;

        // https://man7.org/linux/man-pages/man7/cgroups.7.html
        // https://www.kernel.org/doc/Documentation/cgroup-v1/freezer-subsystem.txt
        // https://www.containerlabs.kubedaily.com/LXC/Linux%20Containers/The-cgroup-freezer-subsystem.html

        mkdir("/dev/jark_freezer", 0666);
        mount("freezer", "/dev/jark_freezer", "cgroup", 0, "freezer");
        usleep(1000 * 100);
        mkdir("/dev/jark_freezer/frozen", 0666);
        mkdir("/dev/jark_freezer/unfrozen", 0666);
        usleep(1000 * 100);
        Utils::writeString("/dev/jark_freezer/frozen/freezer.state", "FROZEN");
        Utils::writeString("/dev/jark_freezer/unfrozen/freezer.state", "THAWED");

        // https://www.spinics.net/lists/cgroups/msg24540.html
        // https://android.googlesource.com/device/google/crosshatch/+/9474191%5E%21/
        Utils::writeString("/dev/jark_freezer/frozen/freezer.killable", "1"); // 旧版内核不支持
        usleep(1000 * 100);

        return (!access(cgroupV1FrozenPath, F_OK) && !access(cgroupV1UnfrozenPath, F_OK));
    }

    bool checkFreezerV2UID() {
        return (!access(cgroupV2FreezerCheckPath, F_OK));
    }

    bool checkFreezerV2FROZEN() {
        return (!access(cgroupV2frozenCheckPath, F_OK) && !access(cgroupV2unfrozenCheckPath, F_OK));
    }

    void checkAndMountV2() {
        // https://cs.android.com/android/kernel/superproject/+/common-android12-5.10:common/kernel/cgroup/freezer.c

        if (checkFreezerV2UID())
            freezeit.log("原生支持 FreezerV2(UID)");

        if (checkFreezerV2FROZEN()) {
            freezeit.log("原生支持 FreezerV2(FROZEN)");
        }
        else {
            mkdir("/sys/fs/cgroup/frozen/", 0666);
            mkdir("/sys/fs/cgroup/unfrozen/", 0666);
            usleep(1000 * 500);

            if (checkFreezerV2FROZEN()) {
                auto fd = open(cgroupV2frozenCheckPath, O_WRONLY | O_TRUNC);
                if (fd > 0) {
                    write(fd, "1", 2);
                    close(fd);
                }
                freezeit.logFmt("设置%s FreezerV2(FROZEN)", fd > 0 ? "成功" : "失败");

                fd = open(cgroupV2unfrozenCheckPath, O_WRONLY | O_TRUNC);
                if (fd > 0) {
                    write(fd, "0", 2);
                    close(fd);
                }
                freezeit.logFmt("设置%s FreezerV2(UNFROZEN)", fd > 0 ? "成功" : "失败");

                freezeit.log("现已支持 FreezerV2(FROZEN)");
            }
        }
    }

    void printProcState() {
        START_TIME_COUNT;

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            freezeit.logFmt("错误: %s(), [%d]:[%s]\n", __FUNCTION__, errno, strerror(errno));
            return;
        }

        //int getSignalCnt = 0;
        int totalMiB = 0;
        set<int> uidSet, pidSet;

        lock_guard<mutex> lock(naughtyMutex);
        naughtyApp.clear();

        stackString<1024 * 16> stateStr("进程冻结状态:\n\n PID | MiB |  状 态  | 进 程\n");

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            const int uid = statBuf.st_uid;
            if (!managedApp.contains(uid)) continue;

            auto& appInfo = managedApp[uid];
            if (appInfo.isWhitelist()) continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256]; // now is cmdline Content
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const auto& package = appInfo.package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;
            const char endChar = readBuff[package.length()]; // 特例 com.android.chrome_zygote 无法binder冻结
            if (endChar != ':' && endChar != 0)continue;

            uidSet.insert(uid);
            pidSet.insert(pid);

            stackString<256> label(appInfo.label.c_str(), appInfo.label.length());
            if (readBuff[appInfo.package.length()] == ':')
                label.append(readBuff + appInfo.package.length());

            memcpy(fullPath + 6, file->d_name, 6);
            strcat(fullPath + 8, "/statm");
            Utils::readString(fullPath, readBuff, sizeof(readBuff)); // now is statm content
            const char* ptr = strchr(readBuff, ' ');

            // Unit: 1 page(4KiB) convert to MiB. (atoi(ptr) * 4 / 1024)
            const int memMiB = ptr ? (atoi(ptr + 1) >> 8) : 0;
            totalMiB += memMiB;

            if (curForegroundApp.contains(uid)) {
                stateStr.appendFmt("%5d %4d 📱正在前台 %s\n", pid, memMiB, label.c_str());
                continue;
            }

            if (pendingHandleList.contains(uid)) {
                const auto secRemain = pendingHandleList[uid];
                if (secRemain < 60)
                    stateStr.appendFmt("%5d %4d ⏳%d秒后冻结 %s\n", pid, memMiB, secRemain, label.c_str());
                else
                    stateStr.appendFmt("%5d %4d ⏳%d分后冻结 %s\n", pid, memMiB, secRemain / 60, label.c_str());
                continue;
            }

            memcpy(fullPath + 6, file->d_name, 6);
            strcat(fullPath + 8, "/wchan");
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0) {
                uidSet.erase(uid);
                pidSet.erase(pid);
                continue;
            }

            stateStr.appendFmt("%5d %4d ", pid, memMiB);
            if (!strcmp(readBuff, v2wchan)) {
                stateStr.appendFmt("❄️V2冻结中 %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, v1wchan)) {
                stateStr.appendFmt("❄️V1冻结中 %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, SIGSTOPwchan)) {
                stateStr.appendFmt("🧊ST冻结中 %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, v2xwchan)) {
                stateStr.appendFmt("❄️V2*冻结中 %s\n", label.c_str());
                //getSignalCnt++;
            }
            else if (!strcmp(readBuff, pStopwchan)) {
                stateStr.appendFmt("🧊ST冻结中(ptrace_stop) %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, binder_wchan)) {
                stateStr.appendFmt("⚠️运行中(Binder通信) %s\n", label.c_str());
                naughtyApp.insert(uid);
            }
            else if (!strcmp(readBuff, pipe_wchan)) {
                stateStr.appendFmt("⚠️运行中(管道通信) %s\n", label.c_str());
                naughtyApp.insert(uid);
            }
            else if (!strcmp(readBuff, epoll_wait1_wchan) || !strcmp(readBuff, epoll_wait2_wchan)) {
                stateStr.appendFmt("⚠️运行中(就绪态) %s\n", label.c_str());
                naughtyApp.insert(uid);
            }
            else {
                stateStr.appendFmt("⚠️运行中(%s) %s\n", (const char*)readBuff, label.c_str());
                naughtyApp.insert(uid);
            }
        }
        closedir(dir);

        if (uidSet.size() == 0) {
            freezeit.log("后台很干净，一个黑名单应用都没有");
        }
        else {

            if (naughtyApp.size()) {
                stateStr.append("\n 发现 [未冻结状态] 的进程, 即将临时解冻\n");
                refreezeSecRemain = 0;
            }

            stateStr.appendFmt("\n总计 %d 应用 %d 进程, 占用内存 ", (int)uidSet.size(), (int)pidSet.size());
            stateStr.appendFmt("%.2f GiB", totalMiB / 1024.0);
            //if (getSignalCnt)
            //    stateStr.append(", V2*带星号状态为get_signal，小概率非冻结状态");

            freezeit.log(string_view(stateStr.c_str(), stateStr.length));
        }

        if(isReKernelConnected)
            freezeit.logFmt("Re:Kernel上报次数 Binder[%d] 触发[%llu] TCP事件[%llu] UDP事件[%llu] 零长度[%llu] 监听[%d]",
                binderEventCnt, (unsigned long long)netEventCnt,
                (unsigned long long)netTcpSeen, (unsigned long long)netUdpSeen,
                (unsigned long long)netIgnoredZero, (int)netMonitored.size());

        stackString<64> tips;
        int tmp = systemTools.runningTime;
        if (tmp >= 3600) {
            tips.append(tmp / 3600).append("时");
            tmp %= 3600;
        }
        if (tmp >= 60) {
            tips.append(tmp / 60).append("分");
            tmp %= 60;
        }
        tips.append(tmp).append("秒");
        freezeit.logFmt("满电至今已运行 %s", tips.c_str());

        END_TIME_COUNT;
    }

    // 解冻新APP, 旧APP加入待冻结列队
    void updateAppProcess() {
        bool isupdate = false;
        vector<int> newShowOnApp, toBackgroundApp;

        for (const int uid : curForegroundApp)
            if (!lastForegroundApp.contains(uid))
                newShowOnApp.emplace_back(uid);

        for (const int uid : lastForegroundApp)
            if (!curForegroundApp.contains(uid))
                toBackgroundApp.emplace_back(uid);

        if (newShowOnApp.size() || toBackgroundApp.size())
            lastForegroundApp = curForegroundApp;
        else
            return;

        for (const int uid : newShowOnApp) {
            // 如果在待冻结列表则只需移除
            if (pendingHandleList.erase(uid)) {
                isupdate = true;
                continue;
            }

            // 更新[打开时间]  并解冻
            auto& appInfo = managedApp[uid];
            appInfo.startTimestamp = time(nullptr);

            const int num = handleProcess(appInfo, false);
            if (num <= 0) freezeit.logFmt("😁启动 %s", appInfo.label.c_str());
        }

        for (const int uid : toBackgroundApp) { // 更新倒计时
            isupdate = true;
            managedApp[uid].delayCnt = 0;
            pendingHandleList[uid] = managedApp[uid].isTerminateMode() ?
                settings.terminateTimeout : settings.freezeTimeout;
        }

        if (isupdate)
            updatePendingByLocalSocket();
    }

    // 处理待冻结列队 call once per 1sec
    void processPendingApp() {
        bool isupdate = false;

        auto it = pendingHandleList.begin();
        while (it != pendingHandleList.end()) {
            auto& remainSec = it->second;
            if (--remainSec > 0) {//每次轮询减一
                it++;
                continue;
            }

            const int uid = it->first;
            auto& appInfo = managedApp[uid];

            // 最近有入站网络包（下载/推送），不冻结，重新计时
            auto netIt = lastNetEvent.find(uid);
            if (netIt != lastNetEvent.end() && !appInfo.isWhitelist()) {
                const long now = static_cast<long>(time(nullptr));
                if (now - netIt->second < NET_IDLE_SEC) {
                    const int holdSec = settings.freezeTimeout;
                    remainSec = holdSec;
                    freezeit.logFmt("🌐网络活动, 暂不冻结 %s, 重置 %ds",
                        appInfo.label.c_str(), holdSec);
                    it++;
                    continue;
                }
            }

            if (appInfo.isWhitelist()) { // 刚切换成白名单的
                it = pendingHandleList.erase(it);
                continue;
            }

            int num = handleProcess(appInfo, true);
            if (num < 0) {
                if (appInfo.delayCnt >= 5) {
                    handleSignal(appInfo, SIGKILL);
                    freezeit.logFmt("%s:%d 已延迟%d次, 强制杀死", appInfo.label.c_str(), -num, appInfo.delayCnt);
                    num = 0;
                }
                else {
                    appInfo.delayCnt++;
                    remainSec = 15 << appInfo.delayCnt;
                    freezeit.logFmt("%s:%d Binder正在传输, 第%d次延迟, %d%s 后再冻结", appInfo.label.c_str(), -num,
                        appInfo.delayCnt, remainSec < 60 ? remainSec : remainSec / 60, remainSec < 60 ? "秒" : "分");
                    it++;
                    continue;
                }
            }
            it = pendingHandleList.erase(it);
            appInfo.delayCnt = 0;

            appInfo.stopTimestamp = time(nullptr);
            const int delta = appInfo.startTimestamp == 0 ? 0 :
                (appInfo.stopTimestamp - appInfo.startTimestamp);
            appInfo.startTimestamp = appInfo.stopTimestamp;
            appInfo.totalRunningTime += delta;
            const int total = appInfo.totalRunningTime;

            stackString<128> timeStr("运行");
            if (delta >= 3600)
                timeStr.appendFmt("%d时", delta / 3600);
            if (delta >= 60)
                timeStr.appendFmt("%d分", (delta % 3600) / 60);
            timeStr.appendFmt("%d秒", delta % 60);

            timeStr.append(" 累计", 7);
            if (total >= 3600)
                timeStr.appendFmt("%d时", total / 3600);
            if (total >= 60)
                timeStr.appendFmt("%d分", (total % 3600) / 60);
            timeStr.appendFmt("%d秒", total % 60);

            if (num)
                freezeit.logFmt("%s冻结 %s %d进程 %s",
                    appInfo.isSignalMode() ? "🧊" : "❄️",
                    appInfo.label.c_str(), num, timeStr.c_str());
            else freezeit.logFmt("😭关闭 %s %s", appInfo.label.c_str(), timeStr.c_str());

            isupdate = true;
        }

        if (isupdate)
            updatePendingByLocalSocket();

    }


    void updatePendingByLocalSocket() {
        START_TIME_COUNT;

        int buff[64] = {};
        int uidCnt = 0;
        for (const auto& [uid, remainSec] : pendingHandleList) {
            buff[uidCnt++] = uid;
            if (uidCnt > 60)
                break;
        }

        const int recvLen = Utils::localSocketRequest(XPOSED_CMD::UPDATE_PENDING, buff,
            uidCnt * sizeof(int), buff, sizeof(buff));

        if (recvLen == 0) {
            freezeit.logFmt("%s() 工作异常, 请确认LSPosed中冻它勾选系统框架, 然后重启", __FUNCTION__);
            END_TIME_COUNT;
            return;
        }
        else if (recvLen != 4) {
            freezeit.logFmt("%s() 返回数据异常 recvLen[%d]", __FUNCTION__, recvLen);
            if (recvLen > 0 && recvLen < 64 * 4)
                freezeit.logFmt("DumpHex: %s", Utils::bin2Hex(buff, recvLen).c_str());
            END_TIME_COUNT;
            return;
        }
        else if (static_cast<REPLY>(buff[0]) == REPLY::FAILURE) {
            freezeit.log("Pending更新失败");
        }
        freezeit.debugFmt("pending更新 %d", uidCnt);
        END_TIME_COUNT;
        return;
    }

    void checkWakeup() {
        timelineIdx = (timelineIdx + 1) & 0x0FFF; // [ %4096]
        const auto uid = unfrozenTimeline[timelineIdx];
        if (uid == 0) return;

        unfrozenTimeline[timelineIdx] = 0;//清掉时间线当前位置UID信息

        if (!managedApp.contains(uid)) return;

        auto& appInfo = managedApp[uid];
        if (appInfo.isSignalOrFreezer()) {
            const int num = handleProcess(appInfo, false);
            if (num > 0) {
                appInfo.startTimestamp = time(nullptr);
                pendingHandleList[uid] = settings.freezeTimeout;//更新待冻结倒计时
                freezeit.logFmt("☀️定时解冻 %s %d进程", appInfo.label.c_str(), num);
            }
            else {
                freezeit.logFmt("🗑️后台被杀 %s", appInfo.label.c_str());
            }
        }
        else {
            appInfo.timelineUnfrozenIdx = -1;
        }
    }


    // 常规查询前台 只返回第三方, 剔除白名单/桌面
    void getVisibleAppByShell() {
        START_TIME_COUNT;

        curForegroundApp.clear();
        const char* cmdList[] = { "/system/bin/cmd", "cmd", "activity", "stack", "list", nullptr };
        VPOPEN::vpopen(cmdList[0], cmdList + 1, getVisibleAppBuff.get(), GET_VISIBLE_BUF_SIZE);

        stringstream ss;
        ss << getVisibleAppBuff.get();

        // 以下耗时仅为 VPOPEN::vpopen 的 2% ~ 6%
        string line;
        while (getline(ss, line)) {
            if (!managedApp.hasHomePackage() && line.find("mActivityType=home") != string::npos) {
                getline(ss, line); //下一行就是桌面信息
                auto startIdx = line.find_last_of('{');
                auto endIdx = line.find_last_of('/');
                if (startIdx == string::npos || endIdx == string::npos || startIdx > endIdx)
                    continue;

                managedApp.updateHomePackage(line.substr(startIdx + 1, endIdx - (startIdx + 1)));
            }

            //  taskId=8655: com.ruanmei.ithome/com.ruanmei.ithome.ui.MainActivity bounds=[0,1641][1440,3200]
            //     userId=0 visible=true topActivity=ComponentInfo{com.ruanmei.ithome/com.ruanmei.ithome.ui.NewsInfoActivity}
            if (!line.starts_with("  taskId=")) continue;
            if (line.find("visible=true") == string::npos) continue;

            auto startIdx = line.find_last_of('{');
            auto endIdx = line.find_last_of('/');
            if (startIdx == string::npos || endIdx == string::npos || startIdx > endIdx) continue;

            const string& package = line.substr(startIdx + 1, endIdx - (startIdx + 1));
            if (!managedApp.contains(package)) continue;
            int uid = managedApp.getUid(package);
            if (managedApp[uid].isWhitelist()) continue;
            curForegroundApp.insert(uid);
        }

        if (curForegroundApp.size() >= (lastForegroundApp.size() + 3)) //有时系统会虚报大量前台应用
            curForegroundApp = lastForegroundApp;

        END_TIME_COUNT;
    }

    void getVisibleAppByLocalSocket() {
        START_TIME_COUNT;

        int buff[64];
        int recvLen = Utils::localSocketRequest(XPOSED_CMD::GET_FOREGROUND, nullptr, 0, buff,
            sizeof(buff));

        int& UidLen = buff[0];
        if (recvLen <= 0) {
            freezeit.logFmt("%s() 工作异常, 请确认LSPosed中冻它勾选系统框架, 然后重启", __FUNCTION__);
            END_TIME_COUNT;
            return;
        }
        else if (UidLen > 16 || (UidLen != (recvLen / 4 - 1))) {
            freezeit.logFmt("%s() 前台服务数据异常 UidLen[%d] recvLen[%d]", __FUNCTION__, UidLen, recvLen);
            freezeit.logFmt("DumpHex: %s", Utils::bin2Hex(buff, recvLen < 64 * 4 ? recvLen : 64 * 4).c_str());
            END_TIME_COUNT;
            return;
        }

        curForegroundApp.clear();
        for (int i = 1; i <= UidLen; i++) {
            int& uid = buff[i];
            if (managedApp.contains(uid)) curForegroundApp.insert(uid);
            else freezeit.logFmt("非法UID[%d], 可能是新安装的应用, 请点击右上角第一个按钮更新应用列表", uid);
        }

#if DEBUG_DURATION
        string tmp;
        for (auto& uid : curForegroundApp)
            tmp += " [" + managedApp[uid].label + "]";
        if (tmp.length())
            freezeit.logFmt("LOCALSOCKET前台%s", tmp.c_str());
        else
            freezeit.log("LOCALSOCKET前台 空");
#endif
        END_TIME_COUNT;
    }


    string getModeText(FREEZE_MODE mode) {
        switch (mode) {
        case FREEZE_MODE::TERMINATE:
            return "杀死后台";
        case FREEZE_MODE::SIGNAL:
            return "SIGSTOP冻结";
        case FREEZE_MODE::SIGNAL_BREAK:
            return "SIGSTOP冻结断网";
        case FREEZE_MODE::FREEZER:
            return "Freezer冻结";
        case FREEZE_MODE::FREEZER_BREAK:
            return "Freezer冻结断网";
        case FREEZE_MODE::WHITELIST:
            return "自由后台";
        case FREEZE_MODE::WHITEFORCE:
            return "自由后台(内置)";
        default:
            return "未知";
        }
    }

    void eventTouchTriggerTask(int n) {
        constexpr int TRIGGER_BUF_SIZE = 8192;

        char touchEventPath[64];
        snprintf(touchEventPath, sizeof(touchEventPath), "/dev/input/event%d", n);

        usleep(n * 1000 * 10);

        int inotifyFd = inotify_init();
        if (inotifyFd < 0) {
            fprintf(stderr, "同步事件: 0xA%d (1/3)失败: [%d]:[%s]", n, errno, strerror(errno));
            exit(-1);
        }

        int watch_d = inotify_add_watch(inotifyFd, touchEventPath, IN_ALL_EVENTS);
        if (watch_d < 0) {
            fprintf(stderr, "同步事件: 0xA%d (2/3)失败: [%d]:[%s]", n, errno, strerror(errno));
            exit(-1);
        }

        freezeit.logFmt("初始化同步事件: 0xA%d", n);

        constexpr int REMAIN_TIMES_MAX = 2;
        char buf[TRIGGER_BUF_SIZE];
        while (read(inotifyFd, buf, TRIGGER_BUF_SIZE) > 0) {
            remainTimesToRefreshTopApp = REMAIN_TIMES_MAX;
            usleep(500 * 1000);
        }

        inotify_rm_watch(inotifyFd, watch_d);
        close(inotifyFd);

        freezeit.logFmt("已退出监控同步事件: 0xA%d", n);
    }

    void cpuSetTriggerTask() {
        constexpr int TRIGGER_BUF_SIZE = 8192;

        sleep(1);

        int inotifyFd = inotify_init();
        if (inotifyFd < 0) {
            fprintf(stderr, "同步事件: 0xB1 (1/3)失败: [%d]:[%s]", errno, strerror(errno));
            exit(-1);
        }

        //int watch_d = inotify_add_watch(inotifyFd,
        //    systemTools.SDK_INT_VER >= 33 ? cpusetEventPathA13
        //    : cpusetEventPathA12,
        //    IN_ALL_EVENTS);

        int watch_d = inotify_add_watch(inotifyFd, cpusetEventPath, IN_ALL_EVENTS);

        if (watch_d < 0) {
            fprintf(stderr, "同步事件: 0xB1 (2/3)失败: [%d]:[%s]", errno, strerror(errno));
            exit(-1);
        }

        freezeit.log("初始化同步事件: 0xB1");

        constexpr int REMAIN_TIMES_MAX = 2;
        char buf[TRIGGER_BUF_SIZE];
        while (read(inotifyFd, buf, TRIGGER_BUF_SIZE) > 0) {
            remainTimesToRefreshTopApp = REMAIN_TIMES_MAX;
            usleep(500 * 1000);
        }

        inotify_rm_watch(inotifyFd, watch_d);
        close(inotifyFd);

        freezeit.log("已退出监控同步事件: 0xB0");
    }

    // 确认某个 UID 正在收数据：重置倒计时 / 需要时解冻
    void applyNetActivity(int uid) {
        const long now = static_cast<long>(time(nullptr));

        if (!managedApp.contains(uid)) return;
        auto& appInfo = managedApp[uid];
        if (!appInfo.isSignalOrFreezer()) return;

        // 重置到应用设置里的“超时冻结”秒数，而不是写死的值
        const int holdSec = settings.freezeTimeout;

        auto it = pendingHandleList.find(uid);
        if (it != pendingHandleList.end()) {
            if (it->second < holdSec) {
                it->second = holdSec;
                if (now - lastNetLog[uid] > 30) {
                    lastNetLog[uid] = now;
                    freezeit.logFmt("🌐网络活动, %s 冻结倒计时重置 %ds",
                        appInfo.label.c_str(), holdSec);
                }
            }
            return;
        }

        if (curForegroundApp.contains(uid)) return;

        // 一次下载会连发大量事件：解冻本身要扫 /proc，这里 10 秒内只做一次。
        // 之后该 UID 已在 curForegroundApp 里，重复事件会在上面直接返回。
        if (now - lastNetUnfreeze[uid] < 10) return;
        lastNetUnfreeze[uid] = now;

        unFreezerTemporary(uid);
        if (now - lastNetLog[uid] > 30) {
            lastNetLog[uid] = now;
            freezeit.logFmt("🌐网络解冻 %s", appInfo.label.c_str());
        }
    }

    // 把受管应用（冻结/信号模式）注册到内核的网络监听表；不再需要的显式 DEL，
    // 因为内核的 UID 监控表是全局的，进程退出也不会自动清。
    void syncNetMonitor(rekernelGenl::Client& genl) {
        int removed = 0, added = 0, failed = 0, total = 0, lastSubError = 0;

        // 设置页的 Re:Kernel 阈值：变了就重发一遍订阅（内核侧 ADD 即更新语义）
        const uint32_t wantTcp = static_cast<uint32_t>(settings.getNetMinPayloadTcp());
        const uint32_t wantUdp = static_cast<uint32_t>(settings.getNetMinPayloadUdp());
        const bool thresholdChanged = wantTcp != netAppliedTcp || wantUdp != netAppliedUdp;
        if (thresholdChanged) {
            for (const int uid : netMonitored) {
                int err = 0;
                genl.addMonitorNet(static_cast<uint32_t>(uid), wantTcp, wantUdp, &err);
            }
            netAppliedTcp = wantTcp;
            netAppliedUdp = wantUdp;
            if (!netMonitored.empty()) {
                freezeit.logFmt("Re:Kernel 阈值已更新 TCP≥%uB UDP≥%uB（0=内核默认），重订阅 %d 个应用",
                    wantTcp, wantUdp, (int)netMonitored.size());
            }
        }

        for (auto it = netMonitored.begin(); it != netMonitored.end();) {
            const int uid = *it;
            const bool keep = managedApp.contains(uid) && managedApp[uid].isSignalOrFreezer();
            if (keep) {
                ++it;
                continue;
            }
            int err = 0;
            if (genl.delMonitorNet(static_cast<uint32_t>(uid), &err)) {
                removed++;
            }
            // 应用已卸载/改成白名单：无论 DEL 是否成功都不再计入
            it = netMonitored.erase(it);
        }

        for (int uid = ManagedApp::UID_START; uid < ManagedApp::UID_END; ++uid) {
            if (!managedApp.contains(uid)) continue;
            if (!managedApp[uid].isSignalOrFreezer()) continue;

            total++;
            if (netMonitored.contains(uid)) continue;

            int err = 0;
            if (genl.addMonitorNet(static_cast<uint32_t>(uid), wantTcp, wantUdp, &err)) {
                netMonitored.insert(uid);
                added++;
                if (added <= 5)
                    freezeit.logFmt("🌐监听已加 %s uid=%d",
                        managedApp[uid].label.c_str(), uid);
            }
            else {
                failed++;
                lastSubError = err;
                if (failed <= 3)
                    freezeit.logFmt("🌐网络监听订阅失败 uid=%d 内核错误=%d",
                        uid, err);
            }
        }

        // 新增/取消/失败时立刻打；其余每 10 分钟报一次总数，免得 5 秒一条刷屏
        const long now = static_cast<long>(time(nullptr));
        if (added || removed || failed || now - lastNetSummary >= 600) {
            lastNetSummary = now;
            if (total == 0)
                freezeit.log("Re:Kernel 网络监听: 没有可订阅的应用(需冻结/信号模式)");
            else
                freezeit.logFmt("Re:Kernel 网络监听 %d/%d 应用 (新增%d 取消%d 失败%d 错误码%d)",
                    (int)netMonitored.size(), total, added, removed, failed, lastSubError);
        }
    }

    // 解析 "type=Network,target=<uid>,proto=ipv4|ipv6,dir=in|out,l4=tcp|udp,data_len=<n>;"
    // 旧版内核没有 dir/l4 字段，按入向 TCP 兼容处理。
    static bool parseNetEvent(const char* msg, int& uid, int& dataLen, bool& ipv6,
                              bool& udp, bool& outbound) {
        if (strncmp(msg, "type=Network", 12) != 0) return false;
        const char* p = strstr(msg, "target=");
        if (p == nullptr) return false;

        uid = atoi(p + 7);
        dataLen = -1; // 旧版协议可能没有该字段，按“有活动”处理
        ipv6 = false;
        udp = false;
        outbound = false;

        p = strstr(msg, "data_len=");
        if (p != nullptr) dataLen = atoi(p + 9);
        p = strstr(msg, "proto=");
        if (p != nullptr && strncmp(p + 6, "ipv6", 4) == 0) ipv6 = true;
        p = strstr(msg, "l4=");
        if (p != nullptr && strncmp(p + 3, "udp", 3) == 0) udp = true;
        p = strstr(msg, "dir=");
        if (p != nullptr && strncmp(p + 4, "out", 3) == 0) outbound = true;
        return true;
    }

    // Re:Kernel 事件处理，genl 与旧 netlink 共用
    // 返回 true 表示这是 Binder 事件（用于计数）
    bool handleReKernelEvent(const char* msg) {
        const bool isBinder = strncmp(msg, "type=Binder", 11) == 0;

        int uid = 0, dataLen = -1;
        bool ipv6 = false, udp = false, outbound = false;
        if (parseNetEvent(msg, uid, dataLen, ipv6, udp, outbound)) {
            if (uid <= 0) return false;
            // 全量广播的内核模块会把所有应用的包都发过来，这里只处理受管应用，
            // 避免首次事件日志和计数被系统应用刷屏。
            if (!managedApp.contains(uid) || !managedApp[uid].isSignalOrFreezer()) return false;

            const long now = static_cast<long>(time(nullptr));

            // 统计所有 data_len>0 的事件（含未达到触发阈值的），用于确认 UDP 通道是否真的通了
            if (dataLen > 0) {
                if (udp) netUdpSeen++; else netTcpSeen++;
                if (udp && netUdpSeenUid.insert(uid).second) {
                    freezeit.logFmt("🌐UDP事件 %s uid=%d dir=%s data_len=%d",
                        managedApp[uid].label.c_str(), uid,
                        outbound ? "out" : "in", dataLen);
                }
            }

            // data_len=0：握手/纯 ACK。单看它不是下载，但上传时对端 ACK
            // 会让这个计数快速上涨，用窗口计数间接识别出方向流量。
            if (dataLen == 0) {
                netIgnoredZero++;
                if (netZeroSeen.insert(uid).second) {
                    freezeit.logFmt("🌐零长度事件 %s uid=%d (握手/ACK，通道已通)",
                        managedApp.contains(uid) ? managedApp[uid].label.c_str() : "?",
                        uid);
                }
                auto& w = netZeroWin[uid];
                if (w.start == 0 || now - w.start >= NET_ZERO_WINDOW_SEC) {
                    w.start = now;
                    w.cnt = 0;
                }
                if (++w.cnt < NET_ZERO_ACTIVE_CNT) return false;

                w.cnt = 0;
                lastNetEvent[uid] = now;
                netEventCnt++;
                if (netOutSeen.insert(uid).second) {
                    freezeit.logFmt("🌐疑似上传活动 %s uid=%d 10秒内零长度包≥%d",
                        managedApp.contains(uid) ? managedApp[uid].label.c_str() : "?",
                        uid, NET_ZERO_ACTIVE_CNT);
                }
                applyNetActivity(uid);
                return false;
            }

            // TCP：单包 >=4KB（GRO 合并）直接算；否则要 3 秒内至少 4 个 >=1KB 的包。
            // UDP：阈值更低（>=2KB 直接算，否则 3 秒内 4 个 >=512B），因为视频
            // 通话的 RTC 包本身就在 600B~1.2KB 区间。
            const int minBytes = udp ? NET_UDP_MIN_BYTES : NET_EVENT_MIN_BYTES;
            const int bigBytes = udp ? NET_UDP_BIG_EVENT_BYTES : NET_BIG_EVENT_BYTES;
            bool active = false;
            if (dataLen >= bigBytes) {
                active = true;
            } else if (dataLen >= minBytes) {
                auto& w = udp ? netRateWinUdp[uid] : netRateWin[uid];
                if (w.start == 0 || now - w.start >= NET_BURST_WINDOW_SEC) {
                    w.start = now;
                    w.cnt = 0;
                }
                if (++w.cnt >= NET_BURST_MIN_EVENTS) {
                    w.cnt = 0;
                    w.start = now;
                    active = true;
                }
            }
            if (!active) return false;

            // 同一秒只处理一次，下载时不必每个包都走一遍倒计时/解冻判断
            if (lastNetTrigger[uid] == now) return false;
            lastNetTrigger[uid] = now;

            lastNetEvent[uid] = now;
            netEventCnt++;
            if (netSeenUid.insert(uid).second) {
                freezeit.logFmt("🌐网络事件已生效 %s uid=%d proto=%s dir=%s l4=%s data_len=%d",
                    managedApp.contains(uid) ? managedApp[uid].label.c_str() : "?",
                    uid, ipv6 ? "ipv6" : "ipv4", outbound ? "out" : "in",
                    udp ? "udp" : "tcp", dataLen);
            }
            applyNetActivity(uid);
            return false;
        }

        // Binder 只对“同步的 transaction”解冻：reply / oneway / free_buffer_full
        // 不会阻塞调用方，没必要把刚冻结的 QQ 又拉起来。
        if (strstr(msg, "bindertype=transaction") == nullptr) return isBinder;
        if (strstr(msg, "oneway=1") != nullptr) return isBinder;

        auto ptr = strstr(msg, "target=");
        if (ptr == nullptr) return isBinder;
        const int targetUid = atoi(ptr + 7);

        if (!managedApp.contains(targetUid)) return isBinder;

        auto& appInfo = managedApp[targetUid];
        if (!appInfo.isSignalOrFreezer()) return isBinder;
        if (curForegroundApp.contains(targetUid)) return isBinder;
        if (pendingHandleList.contains(targetUid)) return isBinder;

        // 按用户要求：Binder 事件不再解冻，保持冻结状态。
        // 只留一条 60 秒节流的日志，方便确认 Binder 通道在工作。
        const long now = static_cast<long>(time(nullptr));
        if (now - lastBinderWake[targetUid] < BINDER_WAKE_COOLDOWN_SEC) return isBinder;
        lastBinderWake[targetUid] = now;

        freezeit.logFmt("Binder事件 %s（保持冻结）", appInfo.label.c_str());
        return isBinder;
    }

    // 新版 Re:Kernel(11+) 默认 Generic Netlink，不再创建 /proc/rekernel
    void binderEventTriggerTask() {
        while (true) {
            rekernelGenl::Client genl;
            if (!genl.open()) break; // 非 genl 版本或未安装，转旧协议

            char ver[64] = {};
            if (genl.queryVersion(ver, sizeof(ver)))
                freezeit.logFmt("Re:Kernel(genl) 已连接 family=%u group=%u 内核版本=%s",
                    genl.familyId, genl.groupId, ver);
            else
                freezeit.logFmt("Re:Kernel(genl) 已连接 family=%u group=%u (版本查询无响应)",
                    genl.familyId, genl.groupId);
            isReKernelConnected = true;

            netMonitored.clear();
            netZeroSeen.clear();
            syncNetMonitor(genl);

            long lastSync = static_cast<long>(time(nullptr));
            while (true) {
                char msg[256];
                const int n = genl.recvEvent(msg, sizeof(msg));
                if (n < 0) {
                    freezeit.log("Re:Kernel(genl) 接收中断，稍后重连");
                    break;
                }

                // 不能只在 recv 超时时同步：设备上 Binder 事件是连续的，
                // recv 永远等不到 30 秒超时，新启动的应用就永远进不了监听表。
                const long now = static_cast<long>(time(nullptr));
                if (now - lastSync >= NET_SYNC_SEC) {
                    lastSync = now;
                    syncNetMonitor(genl);
                }

                if (n == 0) continue;
                if (handleReKernelEvent(msg))
                    binderEventCnt++;
            }

            genl.close();
            isReKernelConnected = false;
            sleep(60);
        }

        freezeit.log("Re:Kernel: 未发现 genl 接口，尝试旧版 /proc/rekernel");
        legacyBinderEventTask();
    }

    // 旧版 Re:Kernel：/proc/rekernel/<端口> + raw netlink
    void legacyBinderEventTask() {
        int skfd;
        int ret;
        user_msg_info u_info{};
        socklen_t len;
        struct sockaddr_nl saddr {}, daddr{};
        auto umsg = "Hello! Re:Kernel!";

        DIR* dir = opendir("/proc/rekernel");
        if (dir == nullptr) {
            freezeit.log("ReKernel未安装: /proc/rekernel");
            return;
        }

        auto file = readdir(dir);
        if (file == nullptr) {
            freezeit.log("ReKernel未安装: [ /proc/rekernel ] is empty");
            closedir(dir);
            return;
        }

        const int rekernelPort = atoi(file->d_name);
        closedir(dir);

        if (rekernelPort <= 0 || rekernelPort >= 65536) {
            freezeit.logFmt("ReKernelPort端口错误: [%d] [%s]", rekernelPort, file->d_name);
            return;
        }

        struct nlmsghdr* nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PLOAD));

        int failCnt = 0;
        while (true) {
            if (++failCnt > 100) {
                auto tips = "ReKernel 工作异常次数超100次，将退出binder事件监听";
                freezeit.log(tips);
                fprintf(stderr, "%s", tips);
                break;
            }

            skfd = socket(AF_NETLINK, SOCK_DGRAM, rekernelPort);
            if (skfd == -1) {
                freezeit.log("ReKernel AF_NETLINK 创建失败");
                sleep(60);
                continue;
            }

            memset(&saddr, 0, sizeof(saddr));
            saddr.nl_family = AF_NETLINK;
            saddr.nl_pid = USER_PORT;
            saddr.nl_groups = 0;
            if (bind(skfd, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
                close(skfd);

                freezeit.log("ReKernel bind 失败");
                sleep(60);
                continue;
            }

            memset(&daddr, 0, sizeof(daddr));
            daddr.nl_family = AF_NETLINK;
            daddr.nl_pid = 0;
            daddr.nl_groups = 0;

            memset(nlh, 0, sizeof(struct nlmsghdr));
            nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
            nlh->nlmsg_flags = 0;
            nlh->nlmsg_type = 0;
            nlh->nlmsg_seq = 0;
            nlh->nlmsg_pid = saddr.nl_pid;

            memcpy(NLMSG_DATA(nlh), umsg, strlen(umsg));
            //freezeit.logFmt("Send msg to kernel:%s", umsg);

            ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr_nl));
            if (!ret) {
                close(skfd);

                freezeit.log("ReKernel Failed send msg to kernel");
                sleep(60);
                continue;
            }
            isReKernelConnected = true;
            while (true) {
                memset(&u_info, 0, sizeof(u_info));
                len = sizeof(struct sockaddr_nl);
                ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr*)&daddr, &len);
                if (!ret) {
                    freezeit.log("ReKernel Failed recv msg from kernel!");
                    break;
                }

                if (handleReKernelEvent(u_info.msg))
                    binderEventCnt++;
            }

            close(skfd);
            sleep(60);
        }

        free(nlh);
    }


    void cycleThreadFunc() {
        uint32_t halfSecondCnt{ 0 };

        sleep(1);
        getVisibleAppByShell(); // 获取桌面

        while (true) {
            usleep(500 * 1000);

            if (remainTimesToRefreshTopApp > 0) {
                remainTimesToRefreshTopApp--;
                START_TIME_COUNT;
                if (doze.isScreenOffStandby) {
                    if (doze.checkIfNeedToExit()) {
                        curForegroundApp = std::move(curFgBackup); // recovery
                        updateAppProcess();
                        //setWakeupLockByLocalSocket(WAKEUP_LOCK::DEFAULT);//TODO xposed端改为一律禁止
                    }
                }
                else {
                    getVisibleAppByLocalSocket();
                    updateAppProcess(); // ~40us
                }
                END_TIME_COUNT;
            }

            if (++halfSecondCnt & 1) continue;

            systemTools.cycleCnt++;
            systemTools.runningTime++;

            processPendingApp();//1秒一次

            // 2分钟一次 在亮屏状态检测是否已经息屏  息屏状态则检测是否再次强制进入深度Doze
            if (doze.checkIfNeedToEnter()) {
                curFgBackup = std::move(curForegroundApp); //backup
                updateAppProcess();
                //setWakeupLockByLocalSocket(WAKEUP_LOCK::IGNORE); //TODO xposed端改为一律禁止
            }

            if (doze.isScreenOffStandby)continue;// 息屏状态 不用执行 以下功能

            systemTools.checkBattery();// 1分钟一次 电池检测
            checkUnFreeze();// 检查进程状态，按需临时解冻
            checkWakeup();// 检查是否有定时解冻
        }
    }


    void getBlackListUidRunning(set<int>& uids) {
        uids.clear();

        START_TIME_COUNT;

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            char errTips[256];
            snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                strerror(errno));
            fprintf(stderr, "%s", errTips);
            freezeit.log(errTips);
            return;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            const int uid = statBuf.st_uid;
            if (!managedApp.contains(uid) || managedApp[uid].isWhitelist())
                continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256];
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const auto& package = managedApp[uid].package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;
            const char endChar = readBuff[package.length()]; // 特例 com.android.chrome_zygote 无法binder冻结
            if (endChar != ':' && endChar != 0)continue;

            uids.insert(uid);
        }
        closedir(dir);
        END_TIME_COUNT;
    }

    int setWakeupLockByLocalSocket(const WAKEUP_LOCK mode) {
        static set<int> blackListUidRunning;
        START_TIME_COUNT;

        if (mode == WAKEUP_LOCK::IGNORE)
            getBlackListUidRunning(blackListUidRunning);

        if (blackListUidRunning.empty())return 0;

        int buff[64] = { static_cast<int>(blackListUidRunning.size()), static_cast<int>(mode) };
        int i = 2;
        for (const int uid : blackListUidRunning)
            buff[i++] = uid;

        const int recvLen = Utils::localSocketRequest(XPOSED_CMD::SET_WAKEUP_LOCK, buff,
            i * sizeof(int), buff, sizeof(buff));

        if (recvLen == 0) {
            freezeit.logFmt("%s() 工作异常, 请确认LSPosed中冻它勾选系统框架, 然后重启", __FUNCTION__);
            END_TIME_COUNT;
            return 0;
        }
        else if (recvLen != 4) {
            freezeit.logFmt("%s() 返回数据异常 recvLen[%d]", __FUNCTION__, recvLen);
            if (recvLen > 0 && recvLen < 64 * 4)
                freezeit.logFmt("DumpHex: %s", Utils::bin2Hex(buff, recvLen).c_str());
            END_TIME_COUNT;
            return 0;
        }
        END_TIME_COUNT;
        return buff[0];
    }

    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/am/CachedAppOptimizer.java;l=753
    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/jni/com_android_server_am_CachedAppOptimizer.cpp;l=475
    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/native/libs/binder/IPCThreadState.cpp;l=1564
    // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/drivers/android/binder.c;l=5615
    // https://elixir.bootlin.com/linux/latest/source/drivers/android/binder.c#L5412

    // 0成功  小于0为操作失败的pid
    int handleBinder(appInfoStruct& appInfo, const bool freeze) {
        if (bs.fd <= 0)return 0;

        START_TIME_COUNT;

        // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/drivers/android/binder.c;l=5434
        // 100ms 等待传输事务完成
        binder_freeze_info binderInfo{ .pid = 0u, .enable = freeze ? 1u : 0u, .timeout_ms = 0u };
        binder_frozen_status_info statusInfo = { 0, 0, 0 };

        if (freeze) { // 冻结
            for (size_t i = 0; i < appInfo.pids.size(); i++) {
                binderInfo.pid = appInfo.pids[i];
                if (ioctl(bs.fd, BINDER_FREEZE, &binderInfo) < 0) {
                    int errorCode = errno;

                    // ret == EAGAIN indicates that transactions have not drained.
                    // Call again to poll for completion.
                    switch (errorCode) {
                    case EAGAIN: // 11
                        break;
                    case EINVAL:  // 22  酷安经常有某进程无法冻结binder
                        break;
                    default:
                        freezeit.logFmt("冻结 Binder 发生异常 [%s:%u] ErrorCode:%d", appInfo.label.c_str(), binderInfo.pid, errorCode);
                        break;
                    }

                    // 解冻已经被冻结binder的进程
                    binderInfo.enable = 0;
                    for (size_t j = 0; j < i; j++) {
                        binderInfo.pid = appInfo.pids[j];

                        //TODO 如果解冻失败？
                        if (ioctl(bs.fd, BINDER_FREEZE, &binderInfo) < 0) {
                            errorCode = errno;
                            freezeit.logFmt("撤消冻结：解冻恢复Binder发生错误：[%s:%u] ErrorCode:%d", appInfo.label.c_str(), binderInfo.pid, errorCode);
                        }
                    }
                    return -appInfo.pids[i];
                }
            }

            usleep(1000 * 200);

            for (size_t i = 0; i < appInfo.pids.size(); i++) {
                statusInfo.pid = appInfo.pids[i];
                if (ioctl(bs.fd, BINDER_GET_FROZEN_INFO, &statusInfo) < 0) {
                    int errorCode = errno;
                    freezeit.logFmt("获取 [%s:%d] Binder 状态错误 ErrroCode:%d", appInfo.label.c_str(), statusInfo.pid, errorCode);
                }
                else if (statusInfo.sync_recv & 0b0010) { // 冻结后发现仍有传输事务
                    freezeit.logFmt("%s 仍有Binder传输事务", appInfo.label.c_str());

                    // 解冻全部进程
                    binderInfo.enable = 0;
                    for (size_t j = 0; j < appInfo.pids.size(); j++) {
                        binderInfo.pid = appInfo.pids[j];

                        //TODO 如果解冻失败？
                        if (ioctl(bs.fd, BINDER_FREEZE, &binderInfo) < 0) {
                            int errorCode = errno;
                            freezeit.logFmt("撤消冻结：解冻恢复Binder发生错误：[%s:%u] ErrorCode:%d", appInfo.label.c_str(), binderInfo.pid, errorCode);
                        }
                    }
                    return -appInfo.pids[i];
                }
            }
        }
        else { // 解冻
            set<int> hasSync;

            for (size_t i = 0; i < appInfo.pids.size(); i++) {
                statusInfo.pid = appInfo.pids[i];
                if (ioctl(bs.fd, BINDER_GET_FROZEN_INFO, &statusInfo) < 0) {
                    int errorCode = errno;
                    freezeit.logFmt("获取 [%s:%d] Binder 状态错误 ErrroCode:%d", appInfo.label.c_str(), statusInfo.pid, errorCode);
                }
                else {
                    // 注意各个二进制位差别
                    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/jni/com_android_server_am_CachedAppOptimizer.cpp;l=489
                    // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/drivers/android/binder.c;l=5467
                    if (statusInfo.sync_recv & 1) {
                        freezeit.debugFmt("[%s:%d] 冻结期间存在 同步传输 Sync transactions, 杀掉进程", appInfo.label.c_str(), statusInfo.pid);
                        //TODO 要杀掉进程
                        hasSync.insert(statusInfo.pid);
                    }
                    if (statusInfo.async_recv & 1) {
                        freezeit.debugFmt("[%s:%d] 冻结期间存在 异步传输（不重要）", appInfo.label.c_str(), statusInfo.pid);
                    }
                    if (statusInfo.sync_recv & 0b0010) {
                        freezeit.debugFmt("[%s:%d] 冻结期间存在“未完成”传输（不重要）TXNS_PENDING", appInfo.label.c_str(), statusInfo.pid);
                    }
                }
            }


            if (hasSync.size()) {
                for (auto it = appInfo.pids.begin(); it != appInfo.pids.end();) {
                    if (hasSync.contains(*it)) {
                        freezeit.debugFmt("杀掉进程 pid: %d", *it);
                        kill(*it, SIGKILL);
                        it = appInfo.pids.erase(it);
                    }
                    else {
                        it++;
                    }
                }
            }

            for (size_t i = 0; i < appInfo.pids.size(); i++) {
                binderInfo.pid = appInfo.pids[i];
                if (ioctl(bs.fd, BINDER_FREEZE, &binderInfo) < 0) {
                    int errorCode = errno;
                    freezeit.logFmt("解冻 Binder 发生异常 [%s:%u] ErrorCode:%d", appInfo.label.c_str(), binderInfo.pid, errorCode);

                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "/proc/%d/cmdline", binderInfo.pid);
                        
                    freezeit.logFmt("cmdline:[%s]", Utils::readString(tmp).c_str());

                    if (access(tmp, F_OK)) {
                        freezeit.logFmt("进程已不在 [%s:%u] ", appInfo.label.c_str(), binderInfo.pid);
                    }
                    //TODO 再解冻一次，若失败，考虑杀死？
                    else if (ioctl(bs.fd, BINDER_FREEZE, &binderInfo) < 0) {
                        errorCode = errno;
                        freezeit.logFmt("重试解冻 Binder 发生异常 [%s:%u] ErrorCode:%d", appInfo.label.c_str(), binderInfo.pid, errorCode);
                    }
                }
            }
        }

        END_TIME_COUNT;
        return 0;
    }

    void binder_close() {
        munmap(bs.mapped, bs.mapSize);
        close(bs.fd);
        bs.fd = -1;
    }

    void binderInit(const char* driver) {
        bs.fd = open(driver, O_RDWR | O_CLOEXEC);
        if (bs.fd < 0) {
            freezeit.logFmt("Binder初始化失败 路径打开失败：[%s] [%d:%s]", driver, errno, strerror(errno));
            return;
        }

        struct binder_version b_ver { -1 };
        if ((ioctl(bs.fd, BINDER_VERSION, &b_ver) < 0) ||
            (b_ver.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
            freezeit.logFmt("Binder初始化失败 binder版本要求: %d  本机版本: %d", BINDER_CURRENT_PROTOCOL_VERSION,
                b_ver.protocol_version);
            close(bs.fd);
            bs.fd = -1;
            return;
        }
        else {
            freezeit.logFmt("初始驱动 BINDER协议版本 %d", b_ver.protocol_version);
        }

        // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/jni/com_android_server_am_CachedAppOptimizer.cpp;l=489
        binder_frozen_status_info info = { (uint32_t)getpid(), 0, 0 };
        if (ioctl(bs.fd, BINDER_GET_FROZEN_INFO, &info) < 0) {
            int ret = -errno;
            freezeit.logFmt("Binder初始化失败 不支持 BINDER_FREEZER 特性 ErrroCode:%d", ret);
            close(bs.fd);
            bs.fd = -1;
            return;
        }
        else {
            freezeit.log("特性支持 BINDER_FREEZER");
        }

        bs.mapped = mmap(NULL, bs.mapSize, PROT_READ, MAP_PRIVATE, bs.fd, 0);
        if (bs.mapped == MAP_FAILED) {
            freezeit.logFmt("Binder初始化失败 Binder mmap失败 [%s] [%d:%s]", driver, errno, strerror(errno));
            close(bs.fd);
            bs.fd = -1;
            return;
        }
    }    
};
