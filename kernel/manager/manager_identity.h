#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>

#define KSU_INVALID_APPID -1
#define KSU_PER_USER_RANGE 100000

#define KSU_MAX_MANAGERS 8

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

static inline void ksu_invalidate_manager_uid()
{
}

static inline int ksu_caller_profile_index(void)
{
    return -1;
}
#else
// Several managers can be active at once. Slots are written under the throne
// tracker mutex; ksu_active_manager_count is published last (WRITE_ONCE) so a
// lockless reader never sees a slot that is not fully written.
struct ksu_active_manager {
	uid_t appid;
	int profile_index; // index into ksu_manager_profiles[], -1 = native
};

extern struct ksu_active_manager ksu_active_managers[KSU_MAX_MANAGERS]; // DO NOT DIRECT USE
extern int ksu_active_manager_count; // DO NOT DIRECT USE

static inline bool ksu_is_manager_appid_valid()
{
	return READ_ONCE(ksu_active_manager_count) > 0;
}

static inline bool is_uid_manager(uid_t uid)
{
	uid_t appid = uid % KSU_PER_USER_RANGE;
	int n = READ_ONCE(ksu_active_manager_count);
	int i;

	for (i = 0; i < n; i++) {
		if (ksu_active_managers[i].appid == appid)
			return true;
	}
	return false;
}

static inline bool is_manager()
{
	return is_uid_manager(current_uid().val);
}

static inline uid_t ksu_get_manager_appid()
{
	if (READ_ONCE(ksu_active_manager_count) > 0)
		return ksu_active_managers[0].appid;
	return KSU_INVALID_APPID;
}

// Manual override (CHANGE_MANAGER_UID / debug): collapse to a single native slot.
static inline void ksu_set_manager_appid(uid_t appid)
{
	ksu_active_managers[0].appid = appid;
	ksu_active_managers[0].profile_index = -1;
	WRITE_ONCE(ksu_active_manager_count, 1);
}

static inline void ksu_invalidate_manager_uid()
{
	WRITE_ONCE(ksu_active_manager_count, 0);
}

// Profile index of the manager that issued the current call, or -1.
static inline int ksu_caller_profile_index(void)
{
	uid_t appid = current_uid().val % KSU_PER_USER_RANGE;
	int n = READ_ONCE(ksu_active_manager_count);
	int i;

	for (i = 0; i < n; i++) {
		if (ksu_active_managers[i].appid == appid)
			return ksu_active_managers[i].profile_index;
	}
	return -1;
}
#endif

#endif
