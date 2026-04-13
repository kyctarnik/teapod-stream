/**
 * vpn_helper.cpp
 *
 * JNI helpers for VPN service:
 * - startProcessWithFd: forks tun2socks keeping a specific fd open
 * - killProcess: sends SIGKILL to a process
 *
 * Using fork+exec directly lets us control which file descriptors the child
 * inherits, bypassing Java's ProcessBuilder which closes all non-stdio fds.
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
 * Start a subprocess, keeping `keepFd` open and accessible.
 *
 * Steps:
 * 1. Clear FD_CLOEXEC on keepFd so exec() won't close it
 * 2. fork()
 * 3. In child: exec the command
 * 4. In parent: return child PID
 *
 * @param cmd    Full path to the executable
 * @param args   Command line arguments (including argv[0])
 * @param keepFd File descriptor number to keep open in the child
 * @return child PID on success, negative errno on failure
 */
JNIEXPORT jlong JNICALL
Java_com_teapodstream_teapodstream_XrayVpnService_nativeStartProcessWithFd(
        JNIEnv *env, jclass clazz,
        jstring jCmd, jobjectArray jArgs, jobjectArray jEnvKeys, jobjectArray jEnvVals, jint keepFd, jint maxFds) {

    const char *cmd = env->GetStringUTFChars(jCmd, nullptr);

    int argc = env->GetArrayLength(jArgs);
    char **argv = (char **) malloc((argc + 1) * sizeof(char *));
    for (int i = 0; i < argc; i++) {
        jstring js = (jstring) env->GetObjectArrayElement(jArgs, i);
        argv[i] = (char *) env->GetStringUTFChars(js, nullptr);
    }
    argv[argc] = nullptr;

    // Build environment array
    int envc = jEnvKeys ? env->GetArrayLength(jEnvKeys) : 0;
    char **envp = nullptr;
    if (envc > 0) {
        envp = (char **) malloc((envc + 1) * sizeof(char *));
        for (int i = 0; i < envc; i++) {
            jstring key = (jstring) env->GetObjectArrayElement(jEnvKeys, i);
            jstring val = (jstring) env->GetObjectArrayElement(jEnvVals, i);
            const char *k = env->GetStringUTFChars(key, nullptr);
            const char *v = env->GetStringUTFChars(val, nullptr);
            char *pair = (char *) malloc(strlen(k) + strlen(v) + 2);
            sprintf(pair, "%s=%s", k, v);
            envp[i] = pair;
            env->ReleaseStringUTFChars(key, k);
            env->ReleaseStringUTFChars(val, v);
            env->DeleteLocalRef(key);
            env->DeleteLocalRef(val);
        }
        envp[envc] = nullptr;
    }

    // Clear FD_CLOEXEC on the TUN fd so it survives exec() (only if keepFd is valid)
    if (keepFd >= 0) {
        int flags = fcntl((int) keepFd, F_GETFD);
        if (flags < 0) {
            LOGE("fcntl F_GETFD failed for fd %d: %s", (int) keepFd, strerror(errno));
        } else {
            if (fcntl((int) keepFd, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
                LOGE("fcntl F_SETFD failed for fd %d: %s", (int) keepFd, strerror(errno));
            } else {
                LOGI("Cleared FD_CLOEXEC on fd %d", (int) keepFd);
            }
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        int err = errno;
        LOGE("fork() failed: %s", strerror(err));
        env->ReleaseStringUTFChars(jCmd, cmd);
        for (int i = 0; i < argc; i++) {
            jstring js = (jstring) env->GetObjectArrayElement(jArgs, i);
            env->ReleaseStringUTFChars(js, argv[i]);
        }
        free(argv);
        return (jlong) (-err);
    }

    if (pid == 0) {
        // Child process: 
        // IMPORTANT: Close unused FDs FIRST, then raise limit.
        // setrlimit fails with EPERM if current open fds > new soft limit.
        
        DIR *dir = opendir("/proc/self/fd");
        if (dir != NULL) {
            int dirFd = dirfd(dir);
            struct dirent *ent;
            while ((ent = readdir(dir)) != NULL) {
                int fd = atoi(ent->d_name);
                if (fd > 2 && fd != dirFd) {
                    if (keepFd < 0 || fd != (int) keepFd) {
                        close(fd);
                    }
                }
            }
            closedir(dir);
        }
        
        // Now raise FD limit
        struct rlimit newrl;
        newrl.rlim_cur = (rlim_t) maxFds;
        newrl.rlim_max = (rlim_t) maxFds;
        
        int rc = my_prlimit64(0, RLIMIT_NOFILE, &newrl, nullptr);
        if (rc == 0) {
            LOGI("Child: prlimit64 raised RLIMIT_NOFILE to %d", maxFds);
        } else {
            rc = setrlimit(RLIMIT_NOFILE, &newrl);
            if (rc == 0) {
                LOGI("Child: setrlimit raised RLIMIT_NOFILE to %d", maxFds);
            } else {
                LOGE("Child: Failed to raise RLIMIT_NOFILE, errno=%d (%s)", errno, strerror(errno));
            }
        }
        if (envp) {
            execve(cmd, argv, envp);
        } else {
            execv(cmd, argv);
        }
        _exit(127);
    }

    // Parent process
    LOGI("Forked child pid %d for %s", pid, cmd);
    env->ReleaseStringUTFChars(jCmd, cmd);
    for (int i = 0; i < argc; i++) {
        jstring js = (jstring) env->GetObjectArrayElement(jArgs, i);
        env->ReleaseStringUTFChars(js, argv[i]);
    }
    free(argv);
    
    // Free environment strings
    if (envp) {
        for (int i = 0; envp[i] != nullptr; i++) {
            free(envp[i]);
        }
        free(envp);
    }

    return (jlong) pid;
}

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
