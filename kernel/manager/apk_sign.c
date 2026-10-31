#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/version.h>
#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#include "apk_sign.h"
#include "policy/app_profile.h"
#include "klog.h" // IWYU pragma: keep
#include "compat/kernel_compat.h"

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kzalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
			unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		pr_info("can't alloc sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

static int ksu_sha256(const unsigned char *data, unsigned int datalen,
			unsigned char *digest)
{
	struct crypto_shash *alg;
	char *hash_alg_name = "sha256";
	int ret;

	alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if (IS_ERR(alg)) {
		pr_info("can't alloc alg %s\n", hash_alg_name);
		return PTR_ERR(alg);
	}
	ret = calc_hash(alg, data, datalen, digest);
	crypto_free_shash(alg);
	return ret;
}

static bool read_exact(struct file *fp, void *buffer, size_t size, loff_t *pos,
			loff_t end)
{
	if (*pos < 0 || *pos > end || size > (size_t)(end - *pos))
		return false;
	return ksu_kernel_read_compat(fp, buffer, size, pos) == (ssize_t)size;
}

static bool read_length_prefixed_end(struct file *fp, loff_t *pos,
			loff_t container_end, loff_t *value_end)
{
	u32 length;

	if (!read_exact(fp, &length, sizeof(length), pos, container_end))
		return false;
	if (length > INT_MAX || length > (u64)(container_end - *pos))
		return false;
	*value_end = *pos + length;
	return true;
}

static bool check_block(struct file *fp, loff_t *pos, loff_t block_end,
			unsigned expected_size, const char *expected_sha256)
{
	loff_t signers_end, signer_end, signed_data_end, digests_end, certificates_end;
	u32 certificate_size;
	char cert[1024];
	unsigned char digest[SHA256_DIGEST_SIZE];
	char hash_str[SHA256_DIGEST_SIZE * 2 + 1];

	if (!read_length_prefixed_end(fp, pos, block_end, &signers_end) ||
	    !read_length_prefixed_end(fp, pos, signers_end, &signer_end) ||
	    !read_length_prefixed_end(fp, pos, signer_end, &signed_data_end) ||
	    !read_length_prefixed_end(fp, pos, signed_data_end, &digests_end))
		return false;
	*pos = digests_end;
	if (!read_length_prefixed_end(fp, pos, signed_data_end, &certificates_end) ||
	    !read_exact(fp, &certificate_size, sizeof(certificate_size), pos, certificates_end))
		return false;
	if (certificate_size > INT_MAX || certificate_size > (u64)(certificates_end - *pos) ||
	    certificate_size != expected_size || certificate_size > sizeof(cert))
		return false;
	if (!read_exact(fp, cert, certificate_size, pos, certificates_end))
		return false;
	if (ksu_sha256(cert, certificate_size, digest) < 0)
		return false;
	bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
	hash_str[SHA256_DIGEST_SIZE * 2] = '\0';
	return strcmp(expected_sha256, hash_str) == 0;
}

struct zip_entry_header {
	uint32_t signature;
	uint16_t version;
	uint16_t flags;
	uint16_t compression;
	uint16_t mod_time;
	uint16_t mod_date;
	uint32_t crc32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
	uint16_t file_name_length;
	uint16_t extra_field_length;
} __attribute__((packed));

struct ksu_buf_reader {
	struct file *fp;
	loff_t file_pos;
	char buf[4096];
	size_t buf_len;
};

static inline ssize_t ksu_bread(struct ksu_buf_reader *br, void *dst,
				size_t count, loff_t *pos)
{
	if (*pos >= br->file_pos &&
	    *pos + count <= br->file_pos + br->buf_len) {
		memcpy(dst, br->buf + (*pos - br->file_pos), count);
		*pos += count;
		return count;
	}

	br->file_pos = *pos;
	loff_t read_pos = br->file_pos;
	ssize_t res = ksu_kernel_read_compat(br->fp, br->buf, sizeof(br->buf),
					     &read_pos);
	if (res <= 0) {
		br->buf_len = 0;
		return res;
	}
	br->buf_len = res;

	if (count <= br->buf_len) {
		memcpy(dst, br->buf, count);
		*pos += count;
		return count;
	}

	return 0;
}

// This is a necessary but not sufficient condition, but it is enough for us
static bool has_v1_signature_file(struct file *fp)
{
	struct zip_entry_header header;
	const char MANIFEST[] = "META-INF/MANIFEST.MF";
	bool found = false;
	loff_t pos = 0;

	struct ksu_buf_reader *br =
		kzalloc(sizeof(struct ksu_buf_reader), GFP_KERNEL);
	if (!br) {
		pr_err("ksu_buf_reader alloc failed\n");
		return false;
	}

	br->fp = fp;
	br->file_pos = 0;
	br->buf_len = 0;
	while (ksu_bread(br, &header,
					sizeof(struct zip_entry_header), &pos) ==
		sizeof(struct zip_entry_header)) {
		if (header.signature != 0x04034b50) {
			// ZIP magic: 'PK'
			break;
		}
		// Read the entry file name
		if (header.file_name_length == sizeof(MANIFEST) - 1) {
			char fileName[sizeof(MANIFEST)];
			if (ksu_bread(br, fileName, header.file_name_length,
				      &pos) == header.file_name_length) {
				fileName[header.file_name_length] = '\0';

				// Check if the entry matches META-INF/MANIFEST.MF
				if (strncmp(MANIFEST, fileName, sizeof(MANIFEST) - 1) == 0) {
					found = true;
					break;
				}
			} else {
				break;
			}
		} else {
			// Skip the entry file name
			pos += header.file_name_length;
		}

		// Skip to the next entry
		pos += header.extra_field_length + header.compressed_size;
	}

	kfree(br);
	return found;
}

static __always_inline bool check_v2_signature(const char *path,
						unsigned expected_size,
						const char *expected_sha256)
{
	unsigned char buffer[0x10];
	u32 cd_offset;
	u64 size_of_block, size_of_block_at_head;

	loff_t pos, pairs_end, file_size;

	bool v2_signing_valid = false;
	int v2_signing_blocks = 0;
	struct file *fp = ksu_filp_open_compat(path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err("open %s error.\n", path);
		return false;
	}

	// disable inotify for this file
	fp->f_mode |= FMODE_NONOTIFY;

	// https://en.wikipedia.org/wiki/Zip_(file_format)#End_of_central_directory_record_(EOCD)
	{
		unsigned char *eocd_buffer;
		long search_size;
		long max_comment_size = 0xffff;
		long eocd_min_size = 22;
		long eocd_found = 0;

		file_size = generic_file_llseek(fp, 0, SEEK_END);
		if (file_size < 0)
			goto clean;
		search_size = max_comment_size + eocd_min_size;
		if (search_size > file_size) {
			search_size = file_size;
		}

		eocd_buffer = kvmalloc(search_size, GFP_KERNEL);
		if (!eocd_buffer) {
			pr_err("error: cannot allocate memory for eocd\n");
			goto clean;
		}

		pos = file_size - search_size;
		if (!read_exact(fp, eocd_buffer, search_size, &pos, file_size)) {
			kvfree(eocd_buffer);
			goto clean;
		}

		if (search_size >= eocd_min_size) {
			long j;
			for (j = search_size - eocd_min_size; j >= 0; j--) {
				if (eocd_buffer[j] == 0x50 &&
				    eocd_buffer[j + 1] == 0x4b &&
				    eocd_buffer[j + 2] == 0x05 &&
				    eocd_buffer[j + 3] == 0x06) {
					unsigned short comment_len = 
						eocd_buffer[j + 20] | (eocd_buffer[j + 21] << 8);
					if (comment_len == search_size - j - eocd_min_size) {
						pos = file_size - search_size + j;
						eocd_found = 1;
						break;
					}
				}
			}
		}

		kvfree(eocd_buffer);

		if (!eocd_found) {
			pr_info("error: cannot find eocd\n");
			goto clean;
		}
	}

	pos += 16;
	if (!read_exact(fp, &cd_offset, sizeof(cd_offset), &pos, file_size) ||
	    cd_offset < 0x20 || cd_offset > file_size)
		goto clean;
	pairs_end = (loff_t)cd_offset - 0x18;
	pos = pairs_end;
	if (!read_exact(fp, &size_of_block, sizeof(size_of_block), &pos, cd_offset) ||
	    !read_exact(fp, buffer, sizeof(buffer), &pos, cd_offset) ||
	    memcmp(buffer, "APK Sig Block 42", sizeof(buffer)))
		goto clean;
	if (size_of_block < 0x18 || size_of_block > INT_MAX - 0x8 ||
	    size_of_block > (u64)cd_offset - 0x8)
		goto clean;
	pos = (loff_t)cd_offset - (loff_t)size_of_block - 0x8;
	if (!read_exact(fp, &size_of_block_at_head, sizeof(size_of_block_at_head), &pos, pairs_end) ||
	    size_of_block_at_head != size_of_block)
		goto clean;
	while (pos < pairs_end) {
		u32 id;
		u64 size_of_pair;
		loff_t pair_end;

		if (!read_exact(fp, &size_of_pair, sizeof(size_of_pair), &pos, pairs_end) ||
		    size_of_pair < sizeof(id) || size_of_pair > INT_MAX ||
		    size_of_pair > (u64)(pairs_end - pos))
			goto invalid;
		pair_end = pos + (loff_t)size_of_pair;
		if (!read_exact(fp, &id, sizeof(id), &pos, pair_end))
			goto invalid;
		if (id == 0x7109871au) {
			v2_signing_blocks++;
			v2_signing_valid = check_block(fp, &pos, pair_end, expected_size, expected_sha256);
		} else if (id != 0x42726577u) {
			goto invalid;
		}
		pos = pair_end;
	}

	if (v2_signing_blocks != 1) {
#ifdef CONFIG_KSU_DEBUG
		pr_err("Unexpected v2 signature count: %d\n",
			v2_signing_blocks);
#endif
		v2_signing_valid = false;
	}

	if (v2_signing_valid) {
		int has_v1_signing = has_v1_signature_file(fp);
		if (has_v1_signing) {
			pr_err("Unexpected v1 signature scheme found!\n");
			goto invalid;
		}
	}
	goto clean;
invalid:
	v2_signing_valid = false;
clean:
	filp_close(fp, 0);
	return v2_signing_valid;
}

#ifdef CONFIG_KSU_DEBUG

int ksu_debug_manager_appid = -1;

#include "manager/manager_identity.h"

static int set_expected_size(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_uint(val, kp);
	ksu_set_manager_appid(ksu_debug_manager_appid);
	pr_info("ksu_manager_appid set to %d\n", ksu_debug_manager_appid);
	return rv;
}

static struct kernel_param_ops expected_size_ops = {
	.set = set_expected_size,
	.get = param_get_uint,
};

module_param_cb(ksu_debug_manager_appid, &expected_size_ops,
		&ksu_debug_manager_appid, S_IRUSR | S_IWUSR);

#endif

int get_pkg_from_apk_path(char *pkg, const char *path)
{
	int len = strlen(path);
	if (len >= PATH_MAX || len < 1)
		return -1;

	const char *last_slash = NULL;
	const char *second_last_slash = NULL;

	int i;
	for (i = len - 1; i >= 0; i--) {
		if (path[i] == '/') {
			if (!last_slash) {
				last_slash = &path[i];
			} else {
				second_last_slash = &path[i];
				break;
			}
		}
	}

	if (!last_slash || !second_last_slash)
		return -1;

	const char *last_hyphen = strchr(second_last_slash, '-');
	if (!last_hyphen || last_hyphen > last_slash)
		return -1;

	int pkg_len = last_hyphen - second_last_slash - 1;
	if (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)
		return -1;

	// Copying the package name
	memcpy(pkg, second_last_slash + 1, pkg_len);
	pkg[pkg_len] = '\0';

	return 0;
}

// Manager identity table. cert_size / cert_sha256 recognize the APK; the
// spoof_* fields are auto-returned to that manager on GET_INFO / GET_VERSION_TAG.
// Fill them per manager below; 0 / NULL = use the native kernel value.
//   spoof_version      -> GET_INFO.version       (native: KERNEL_SU_VERSION)
//   spoof_uapi_version -> GET_INFO.uapi_version  (native: KERNEL_SU_UAPI_VERSION)
//   spoof_version_tag  -> GET_VERSION_TAG.tag    (native: KERNEL_SU_VERSION_TAG)
//   spoof_features     -> GET_INFO.features      (native: KSU_FEATURE_MAX)
static const struct ksu_manager_profile ksu_manager_profiles[] = {
	{
		.package = "me.weishu.kernelsu",
		.cert_size = 0x33b,
		.cert_sha256 = "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6",
		.spoof_version = 32680,
		.spoof_uapi_version = 5,
		.spoof_version_tag = NULL,
		.spoof_features = 0,
	},
	{
		.package = "com.rifsxd.ksunext",
		.cert_size = 0x3e6,
		.cert_sha256 = "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7",
		.spoof_version = 33355,
		.spoof_uapi_version = 5,
		.spoof_version_tag = NULL,
		.spoof_features = 0,
	},
	{
		.package = "com.resukisu.resukisu",
		.cert_size = 0x377,
		.cert_sha256 = "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64",
		.spoof_version = 34992,
		.spoof_uapi_version = 5,
		.spoof_version_tag = NULL,
		.spoof_features = 0,
	},
	{
		.package = "wffxxf.nclgit.cawxcw",
		.cert_size = 0x396,
		.cert_sha256 = "f415f4ed9435427e1fdf7f1fccd4dbc07b3d6b8751e4dbcec6f19671f427870b",
		.spoof_version = 0,
		.spoof_uapi_version = 0,
		.spoof_version_tag = NULL,
		.spoof_features = 0,
	},
};

#define KSU_MANAGER_PROFILE_COUNT ARRAY_SIZE(ksu_manager_profiles)

const struct ksu_manager_profile *ksu_get_manager_profile(int index)
{
	if (index < 0 || index >= (int)KSU_MANAGER_PROFILE_COUNT)
		return NULL;

	return &ksu_manager_profiles[index];
}

int ksu_match_manager_apk(const char *path)
{
	char pkg[KSU_MAX_PACKAGE_NAME];
	bool have_pkg = get_pkg_from_apk_path(pkg, path) == 0;
	int i;

	for (i = 0; i < (int)KSU_MANAGER_PROFILE_COUNT; i++) {
		const struct ksu_manager_profile *p = &ksu_manager_profiles[i];

		// cheap reject by package name before the expensive signature check
		if (p->package) {
			if (!have_pkg ||
			    strncmp(pkg, p->package, KSU_MAX_PACKAGE_NAME))
				continue;
		}

		if (check_v2_signature(path, p->cert_size, p->cert_sha256))
			return i;
	}

	return -1;
}

bool is_manager_apk(const char *path)
{
	return ksu_match_manager_apk(path) >= 0;
}
