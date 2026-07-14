package com.surfacevector.bletripwire;

/**
 * Thin JNI surface over nodejs-mobile's libnode.
 *
 * libnode must be loaded before native-lib, since native-lib links against
 * node::Start. Both .so files ship in the APK: libnode.so is placed in
 * jniLibs/&lt;abi&gt;/ by scripts/fetch-libnode.sh, and native-lib.so is built
 * from cpp/ by the NDK.
 */
public final class NodeBridge {

    private static boolean sLoaded = false;

    static synchronized void ensureLoaded() {
        if (sLoaded) return;
        System.loadLibrary("node");        // nodejs-mobile prebuilt
        System.loadLibrary("native-lib");  // our JNI bridge
        sLoaded = true;
    }

    /**
     * Starts Node with the given argv (argv[0] should be "node"). BLOCKS on the
     * Node event loop and only returns when the Node process exits, so call this
     * on a dedicated thread. Returns the Node process exit code.
     */
    public native int startNodeWithArguments(String[] arguments);

    NodeBridge() {}
}
