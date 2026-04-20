#include <jni.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <android/log.h>

#define TAG "TeapodVPN_native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

extern "C" {

JNIEXPORT jint JNICALL
Java_com_teapodstream_teapodstream_XrayVpnService_nativeSetMaxFds(
        JNIEnv *env, jclass clazz, jint maxFds) {
    struct rlimit cur;
    if (getrlimit(RLIMIT_NOFILE, &cur) != 0) return errno;
    LOGI("Current RLIMIT_NOFILE: soft=%lu hard=%lu", cur.rlim_cur, cur.rlim_max);

    struct rlimit newrl;
    newrl.rlim_cur = (rlim_t) maxFds;
    newrl.rlim_max = (rlim_t) maxFds;
    if (setrlimit(RLIMIT_NOFILE, &newrl) != 0) {
        newrl.rlim_cur = cur.rlim_max;
        newrl.rlim_max = cur.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &newrl) != 0) return errno;
    }
    LOGI("RLIMIT_NOFILE set to %lu", newrl.rlim_cur);
    return 0;
}

} // extern "C"
