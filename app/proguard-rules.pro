# Keep the JNI bridge method names — they're resolved by signature from native.
-keepclasseswithmembernames class com.surfacevector.bletripwire.NodeBridge {
    native <methods>;
}
-keep class com.surfacevector.bletripwire.NodeBridge { *; }
