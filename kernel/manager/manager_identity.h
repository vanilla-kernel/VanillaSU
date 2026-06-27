#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>

#define KSU_INVALID_APPID -1
#define KSU_PER_USER_RANGE 100000
#define KSU_MAX_MANAGER_APPIDS 16

#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline bool ksu_is_manager_appid_valid()
{
    return true;
}

static inline bool is_manager()
{
    return current_uid().val == 0;
}

static inline bool is_uid_manager(uid_t uid)
{
    return uid == 0;
}

static inline uid_t ksu_get_manager_appid()
{
    return 0;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
    (void)appid;
}

static inline bool ksu_add_manager_appid(uid_t appid)
{
    (void)appid;
    return true;
}

static inline void ksu_clear_manager_appids()
{
}

static inline void ksu_invalidate_manager_uid()
{
}
#else
extern uid_t ksu_manager_appids[KSU_MAX_MANAGER_APPIDS]; // DO NOT DIRECT USE
extern unsigned int ksu_manager_appid_count; // DO NOT DIRECT USE

static inline bool ksu_is_manager_appid_valid()
{
	return ksu_manager_appid_count > 0;
}

static inline bool ksu_is_manager_appid(uid_t appid)
{
	unsigned int i;

	for (i = 0; i < ksu_manager_appid_count; i++) {
		if (ksu_manager_appids[i] == appid)
			return true;
	}

	return false;
}

static inline bool is_manager()
{
	return unlikely(ksu_is_manager_appid(current_uid().val % KSU_PER_USER_RANGE));
}

static inline bool is_uid_manager(uid_t uid)
{
	return unlikely(ksu_is_manager_appid(uid % KSU_PER_USER_RANGE));
}

static inline uid_t ksu_get_manager_appid()
{
	if (!ksu_is_manager_appid_valid())
		return KSU_INVALID_APPID;

	return ksu_manager_appids[0];
}

static inline void ksu_clear_manager_appids()
{
	ksu_manager_appid_count = 0;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
	ksu_clear_manager_appids();

	if (appid == (uid_t)KSU_INVALID_APPID)
		return;

	ksu_manager_appids[0] = appid;
	ksu_manager_appid_count = 1;
}

static inline bool ksu_add_manager_appid(uid_t appid)
{
	if (appid == (uid_t)KSU_INVALID_APPID)
		return false;

	if (ksu_is_manager_appid(appid))
		return true;

	if (ksu_manager_appid_count >= KSU_MAX_MANAGER_APPIDS)
		return false;

	ksu_manager_appids[ksu_manager_appid_count++] = appid;
	return true;
}

static inline void ksu_invalidate_manager_uid()
{
	ksu_clear_manager_appids();
}
#endif

#endif
