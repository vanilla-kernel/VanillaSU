#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

// One entry per supported manager. The first three fields recognize the APK,
// the spoof_* fields are reported back to that manager via supercall.
// A spoof_* value of 0 / NULL means "report the native build-time value".
struct ksu_manager_profile {
	const char *package; // package name to recognize (NULL = skip package check)
	unsigned int cert_size; // v2 signature certificate length
	const char *cert_sha256; // v2 signature certificate sha256
	u32 spoof_version; // 0 = native KERNEL_SU_VERSION
	u32 spoof_uapi_version; // 0 = native KERNEL_SU_UAPI_VERSION
	const char *spoof_version_tag; // NULL = native KERNEL_SU_VERSION_TAG
	u32 spoof_features; // 0 = native KSU_FEATURE_MAX
};

bool is_manager_apk(char *path);
int get_pkg_from_apk_path(char *pkg, const char *path);

// Returns the index of the matching manager profile, or -1 if none matched.
int ksu_match_manager_apk(char *path);
// Returns the profile at index, or NULL if index is out of range.
const struct ksu_manager_profile *ksu_get_manager_profile(int index);

#endif
