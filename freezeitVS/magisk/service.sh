#!/system/bin/sh
MODDIR=${0%/*}

bootLogPath=$MODDIR/boot.log

# This function is copied from [ Uperf@yc9559 ] module.
wait_until_login() {

    # in case of /data encryption is disabled
    while [ "$(getprop sys.boot_completed)" != "1" ]; do
        sleep 5
    done

    # we doesn't have the permission to rw "/sdcard" before the user unlocks the screen
    # shellcheck disable=SC2039
    local test_file="/sdcard/Android/.PERMISSION_TEST_FREEZEIT"
    true >"$test_file"
    while [ ! -f "$test_file" ]; do
        sleep 5
        true >"$test_file"
    done
    rm "$test_file"
}

echo "[$(date "+%Y-%m-%d %H:%M:%S")] 开始运行服务脚本" >"$bootLogPath"

# ===== 关闭 ColorOS 自带的后台冻结/调度, 后台管理交给冻它 =====
# 放在 wait_until_login 之前, 开机尽早关掉系统侧冻结, 免得抢占冻它的冻结状态
# 仅 ColorOS/OPlus 生效(用 hans.rc 存在性守门), 依据 /system_ext/etc/init/hans.rc:
#   on property:sys.hans.enable=false -> stop hans
# 注意: settings(cmd) 的 stdout 不能直接指向 /data 下的普通文件, 否则报
#       "Failure calling service settings: Failed transaction (2147483646)"
# 注意: 不能在这里 exit, 否则后面的冻它启动不会执行
nohansLog=$MODDIR/nohans.log
if [ -e /system_ext/etc/init/hans.rc ]; then
    {
        echo "[$(date "+%Y-%m-%d %H:%M:%S")] 关闭系统冻结调度"
        # persist 属性会落盘, 这里与 system.prop 重复设置只是兜底
        setprop persist.vendor.enable.hans false
        # 运行时属性不持久, 每次开机必须重设
        setprop sys.hans.enable false
        # AOSP 层 CachedAppOptimizer(cgroup v2), 存 settings 库, 重启保留
        for i in 1 2 3 4 5; do
            settings put global cached_apps_freezer disabled >/dev/null 2>&1 && break
            sleep 2
        done
        freezer=$(settings get global cached_apps_freezer 2>&1)
        echo "[$(date "+%Y-%m-%d %H:%M:%S")] hans=$(getprop init.svc.hans) freezer=$freezer"
    } >> "$nohansLog" 2>&1
    # 兜底重试, 后台跑, 不阻塞冻它启动
    (
        i=0
        while [ $i -lt 10 ]; do
            [ "$(getprop init.svc.hans)" = "running" ] && setprop sys.hans.enable false
            i=$((i+1))
            sleep 3
        done
        echo "[$(date "+%Y-%m-%d %H:%M:%S")] 复核 hans=$(getprop init.svc.hans)" >> "$nohansLog"
    ) >/dev/null 2>&1 &
fi
# ===== end ColorOS 系统冻结 =====

wait_until_login

echo "[$(date "+%Y-%m-%d %H:%M:%S")] 进入桌面, 10秒后将启动冻它" >>"$bootLogPath"

sleep 10

if [ -e "$MODDIR"/disable ] || [ -e "$MODDIR"/remove ]; then
    # shellcheck disable=SC2086
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] 冻它已被禁用或移除，取消启动" >>$bootLogPath
    exit
fi

echo "[$(date "+%Y-%m-%d %H:%M:%S")] 启动冻它" >>"$bootLogPath"

# 带一个任意参数将开启文件式日志 [ /sdcard/Android/freezeit.log ]
# "$MODDIR"/freezeit 0
"$MODDIR"/freezeit
