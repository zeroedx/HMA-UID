// Minimal JNI surface for host-side compilation of the module. Only the
// declarations the module and the Zygisk header reference are provided.
#pragma once
#include <cstdint>

typedef int32_t jint;
typedef uint8_t jboolean;
typedef int64_t jlong;
typedef void* jobject;
typedef void* jstring;
typedef void* jclass;
typedef void* jarray;
typedef void* jobjectArray;
typedef void* jintArray;
typedef void* jmethodID;
typedef void* jfieldID;

typedef struct { const char* name; const char* signature; void* fnPtr; } JNINativeMethod;

struct _JNIEnv {
    const char* GetStringUTFChars(jstring, jboolean*);
    void ReleaseStringUTFChars(jstring, const char*);
};
typedef _JNIEnv JNIEnv;
