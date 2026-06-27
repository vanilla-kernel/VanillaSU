#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

struct ksu_manager_apk_identity {
	const char *package;
	unsigned int cert_size;
	const char *cert_sha256;
	u32 spoof_version;
	bool spoof_uapi_valid;
	u32 spoof_uapi;
	const char *spoof_tag;
};

bool get_manager_apk_identity(char *path,
			      struct ksu_manager_apk_identity *identity);
bool is_manager_apk(char *path);
int get_pkg_from_apk_path(char *pkg, const char *path);

#endif
