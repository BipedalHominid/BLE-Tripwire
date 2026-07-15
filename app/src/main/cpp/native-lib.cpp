// native-lib.cpp — JNI bridge into nodejs-mobile's libnode.
//
// Exposes one native method to Java:
//     int NodeBridge.startNodeWithArguments(String[] args)
// which maps args -> argv and calls node::Start(argc, argv). node::Start is
// BLOCKING: it runs the Node event loop and only returns when the Node process
// exits, so the Java side must call this on its own thread (NodeService does).
//
// It also wires stdout/stderr into logcat. nodejs-mobile has no controlling TTY,
// so without this pump every console.log() from the bundle is silently dropped.
// With it, `adb logcat -s BLUE-SENTINEL-NODE:V` shows the server's output.

#include <jni.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <pthread.h>
#include <android/log.h>

#include "node.h"

#define LOG_TAG "BLUE-SENTINEL-NODE"
#define ALOG(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ---- stdout/stderr -> logcat --------------------------------------------------
static int s_pipe_stdout[2];
static int s_pipe_stderr[2];
static pthread_t s_thread_stdout;
static pthread_t s_thread_stderr;

static void *pump_stdout(void *) {
    ssize_t n;
    char buf[2048];
    while ((n = read(s_pipe_stdout[0], buf, sizeof(buf) - 1)) > 0) {
        if (buf[n - 1] == '\n') n--;
        buf[n] = 0;
        __android_log_write(ANDROID_LOG_INFO, LOG_TAG, buf);
    }
    return nullptr;
}

static void *pump_stderr(void *) {
    ssize_t n;
    char buf[2048];
    while ((n = read(s_pipe_stderr[0], buf, sizeof(buf) - 1)) > 0) {
        if (buf[n - 1] == '\n') n--;
        buf[n] = 0;
        __android_log_write(ANDROID_LOG_WARN, LOG_TAG, buf);
    }
    return nullptr;
}

static void redirect_stdio_to_logcat() {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    if (pipe(s_pipe_stdout) == 0) {
        dup2(s_pipe_stdout[1], STDOUT_FILENO);
        pthread_create(&s_thread_stdout, nullptr, pump_stdout, nullptr);
        pthread_detach(s_thread_stdout);
    }
    if (pipe(s_pipe_stderr) == 0) {
        dup2(s_pipe_stderr[1], STDERR_FILENO);
        pthread_create(&s_thread_stderr, nullptr, pump_stderr, nullptr);
        pthread_detach(s_thread_stderr);
    }
}

// ---- JNI entrypoint -----------------------------------------------------------
extern "C" JNIEXPORT jint JNICALL
Java_com_surfacevector_bletripwire_NodeBridge_startNodeWithArguments(
        JNIEnv *env, jobject /* this */, jobjectArray arguments) {

    redirect_stdio_to_logcat();

    jsize argc = env->GetArrayLength(arguments);

    // node::Start can rewrite argv, so give it heap buffers we own, then free
    // them after it returns (it returns only when Node exits).
    std::vector<char *> argv;
    argv.reserve(static_cast<size_t>(argc) + 1);

    for (jsize i = 0; i < argc; i++) {
        auto js = static_cast<jstring>(env->GetObjectArrayElement(arguments, i));
        const char *utf = env->GetStringUTFChars(js, nullptr);
        argv.push_back(strdup(utf ? utf : ""));
        env->ReleaseStringUTFChars(js, utf);
        env->DeleteLocalRef(js);
    }
    argv.push_back(nullptr);

    ALOG("starting node with %d arg(s); entry=%s", (int) argc, argc > 1 ? argv[1] : "(none)");

    int exit_code = node::Start(static_cast<int>(argc), argv.data());

    ALOG("node::Start returned %d (Node process exited)", exit_code);

    for (char *p : argv) free(p);

    return static_cast<jint>(exit_code);
}
