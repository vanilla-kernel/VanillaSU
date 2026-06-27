#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>

#define KSU_INVALID_APPID -1
#define KSU_PER_USER_RANGE 100000
#define KSU_MAX_MANAGER_APPIDS 16
#define KSU_MANAGER_SPOOF_TAG_LEN 32

struct ksu_manager_spoof {
	u32 version;
	bool uapi_valid;
	u32 uapi;
	char tag[KSU_MANAGER_SPOOF_TAG_LEN];
};

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

static inline u32 ksu_get_manager_spoof_version(uid_t uid)
{
    (void)uid;
    return 0;
}

static inline const char *ksu_get_manager_spoof_tag(uid_t uid)
{
    (void)uid;
    return NULL;
}

static inline bool ksu_get_manager_spoof_uapi(uid_t uid, u32 *uapi)
{
    (void)uid;
    (void)uapi;
    return false;
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

static inline void ksu_replace_manager_appids(const uid_t *appids,
                                              unsigned int count)
{
    (void)appids;
    (void)count;
}

static inline void ksu_replace_manager_appids_with_spoof(
    const uid_t *appids, const struct ksu_manager_spoof *spoofs,
    unsigned int count)
{
    (void)appids;
    (void)spoofs;
    (void)count;
}

static inline void ksu_invalidate_manager_uid()
{
}
#else
extern uid_t ksu_manager_appids[KSU_MAX_MANAGER_APPIDS]; // DO NOT DIRECT USE
extern unsigned int ksu_manager_appid_count; // DO NOT DIRECT USE
extern struct ksu_manager_spoof ksu_manager_spoofs[KSU_MAX_MANAGER_APPIDS]; // DO NOT DIRECT USE

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

static inline const struct ksu_manager_spoof *ksu_get_manager_spoof(uid_t uid)
{
	unsigned int i;
	uid_t appid = uid % KSU_PER_USER_RANGE;

	for (i = 0; i < ksu_manager_appid_count; i++) {
		if (ksu_manager_appids[i] == appid)
			return &ksu_manager_spoofs[i];
	}

	return NULL;
}

static inline u32 ksu_get_manager_spoof_version(uid_t uid)
{
	const struct ksu_manager_spoof *spoof = ksu_get_manager_spoof(uid);

	if (!spoof)
		return 0;

	return spoof->version;
}

static inline const char *ksu_get_manager_spoof_tag(uid_t uid)
{
	const struct ksu_manager_spoof *spoof = ksu_get_manager_spoof(uid);

	if (!spoof || !spoof->tag[0])
		return NULL;

	return spoof->tag;
}

static inline bool ksu_get_manager_spoof_uapi(uid_t uid, u32 *uapi)
{
	const struct ksu_manager_spoof *spoof = ksu_get_manager_spoof(uid);

	if (!spoof || !spoof->uapi_valid || !uapi)
		return false;

	*uapi = spoof->uapi;
	return true;
}

static inline void ksu_clear_manager_appids()
{
	unsigned int i;

	for (i = 0; i < ksu_manager_appid_count; i++) {
		ksu_manager_appids[i] = KSU_INVALID_APPID;
		ksu_manager_spoofs[i].version = 0;
		ksu_manager_spoofs[i].uapi_valid = false;
		ksu_manager_spoofs[i].uapi = 0;
		ksu_manager_spoofs[i].tag[0] = '\0';
	}

	ksu_manager_appid_count = 0;
}

static inline void ksu_replace_manager_appids(const uid_t *appids,
                                              unsigned int count)
{
	unsigned int i;
	unsigned int old_count = ksu_manager_appid_count;

	if (!count) {
		ksu_clear_manager_appids();
		return;
	}

	if (count > KSU_MAX_MANAGER_APPIDS)
		count = KSU_MAX_MANAGER_APPIDS;

	for (i = 0; i < count; i++) {
		ksu_manager_appids[i] = appids[i];
		ksu_manager_spoofs[i].version = 0;
		ksu_manager_spoofs[i].uapi_valid = false;
		ksu_manager_spoofs[i].uapi = 0;
		ksu_manager_spoofs[i].tag[0] = '\0';
	}

	for (; i < old_count; i++) {
		ksu_manager_appids[i] = KSU_INVALID_APPID;
		ksu_manager_spoofs[i].version = 0;
		ksu_manager_spoofs[i].uapi_valid = false;
		ksu_manager_spoofs[i].uapi = 0;
		ksu_manager_spoofs[i].tag[0] = '\0';
	}

	ksu_manager_appid_count = count;
}

static inline void ksu_replace_manager_appids_with_spoof(
	const uid_t *appids, const struct ksu_manager_spoof *spoofs,
	unsigned int count)
{
	unsigned int i;
	unsigned int old_count = ksu_manager_appid_count;

	if (!count) {
		ksu_clear_manager_appids();
		return;
	}

	if (count > KSU_MAX_MANAGER_APPIDS)
		count = KSU_MAX_MANAGER_APPIDS;

	for (i = 0; i < count; i++) {
		ksu_manager_appids[i] = appids[i];
		ksu_manager_spoofs[i] = spoofs[i];
	}

	for (; i < old_count; i++) {
		ksu_manager_appids[i] = KSU_INVALID_APPID;
		ksu_manager_spoofs[i].version = 0;
		ksu_manager_spoofs[i].uapi_valid = false;
		ksu_manager_spoofs[i].uapi = 0;
		ksu_manager_spoofs[i].tag[0] = '\0';
	}

	ksu_manager_appid_count = count;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
	if (appid == (uid_t)KSU_INVALID_APPID) {
		ksu_clear_manager_appids();
		return;
	}

	ksu_replace_manager_appids(&appid, 1);
}

static inline bool ksu_add_manager_appid(uid_t appid)
{
	if (appid == (uid_t)KSU_INVALID_APPID)
		return false;

	if (ksu_is_manager_appid(appid))
		return true;

	if (ksu_manager_appid_count >= KSU_MAX_MANAGER_APPIDS)
		return false;

	ksu_manager_appids[ksu_manager_appid_count] = appid;
	ksu_manager_spoofs[ksu_manager_appid_count].version = 0;
	ksu_manager_spoofs[ksu_manager_appid_count].uapi_valid = false;
	ksu_manager_spoofs[ksu_manager_appid_count].uapi = 0;
	ksu_manager_spoofs[ksu_manager_appid_count].tag[0] = '\0';
	ksu_manager_appid_count++;
	return true;
}

static inline void ksu_invalidate_manager_uid()
{
	ksu_clear_manager_appids();
}
#endif

#endif
