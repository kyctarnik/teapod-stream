/**
 * vpn_helper.cpp
 *
 * JNI helpers for VPN service:
 * - startProcessWithFd: forks a process keeping a specific fd open (legacy/unused)
 * - killProcess: sends SIGKILL to a process
 * - setMaxFds: raises RLIMIT_NOFILE for the process
 */
#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <android/log.h>

// prlimit64 syscall
#ifndef __NR_prlimit64
  #if defined(__aarch64__)
    #define __NR_prlimit64 267
  #elif defined(__arm__)
    #define __NR_prlimit64 370
  #elif defined(__x86_64__)
    #define __NR_prlimit64 302
  #elif defined(__i386__)
    #define __NR_prlimit64 345
  #endif
#endif

static int my_prlimit64(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit) {
#ifdef __NR_prlimit64
    return syscall(__NR_prlimit64, pid, resource, new_limit, old_limit);
#else
    errno = ENOSYS;
    return -1;
#endif
}

#define TAG "TeapodVPN_native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

extern "C" {

/**
 * Send SIGKILL to a process by PID.
 */
JNIEXPORT jint JNICALL
Java_com_teapodstream_teapodstream_XrayVpnService_nativeKillProcess(
        JNIEnv *env, jclass clazz, jlong pid) {
    if (pid <= 0) return -1;
    return kill((pid_t) pid, SIGKILL);
}

/**
 * Проверяет, жив ли процесс по PID (kill с сигналом 0).
 * @return 1 — процесс жив, 0 — мёртв или нет прав.
 */
JNIEXPORT jint JNICALL
Java_com_teapodstream_teapodstream_XrayVpnService_nativeIsProcessAlive(
        JNIEnv *env, jclass clazz, jlong pid) {
    if (pid <= 0) return 0;
    int rc = kill((pid_t) pid, 0);
    return (rc == 0) ? 1 : 0;
}

/**
 * Increase the process's RLIMIT_NOFILE (max open file descriptors).
 * Called before starting xray/tun2socks so child processes inherit the higher limit.
 *
 * @param maxFds desired limit (e.g. 65536)
 * @return 0 on success, errno on failure
 */
JNIEXPORT jint JNICALL
Java_com_teapodstream_teapodstream_XrayVpnService_nativeSetMaxFds(
        JNIEnv *env, jclass clazz, jint maxFds) {
    struct rlimit cur;
    if (getrlimit(RLIMIT_NOFILE, &cur) != 0) return errno;
    LOGI("Current RLIMIT_NOFILE: soft=%lu hard=%lu", cur.rlim_cur, cur.rlim_max);

    struct rlimit newrl;
    newrl.rlim_cur = (rlim_t) maxFds;
    // Can't exceed hard limit; try to raise both, fall back to raising just soft
    newrl.rlim_max = (rlim_t) maxFds;
    if (setrlimit(RLIMIT_NOFILE, &newrl) != 0) {
        // If raising hard limit failed (not root), try just raising soft to current hard
        newrl.rlim_cur = cur.rlim_max;
        newrl.rlim_max = cur.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &newrl) != 0) return errno;
    }
    LOGI("RLIMIT_NOFILE set to %lu", newrl.rlim_cur);
    return 0;
}

} // extern "C"
