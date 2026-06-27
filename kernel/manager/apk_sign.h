#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

struct ksu_manager_apk_identity {
	const char *package;
	unsigned int cert_size;
	const char *cert_sha256;
	const u32 *spoof_ksu_driver_version;
	const u32 *spoof_uapi;
	const char *spoof_ksu_version;
};

bool get_manager_apk_identity(char *path,
			      struct ksu_manager_apk_identity *identity);
bool is_manager_apk(char *path);
int get_pkg_from_apk_path(char *pkg, const char *path);

#endif
