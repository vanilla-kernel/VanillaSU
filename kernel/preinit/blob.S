/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Embed the preinit runner. It is only needed until ksu_preinit_init() copies
 * it into shmem, so keep it in an init section that is freed after load.
 */
	.section .init.rodata, "a"
	.balign 16
	.global ksu_preinit_runner_start
ksu_preinit_runner_start:
#ifdef KSU_PREINIT_RUNNER_BIN
	.incbin KSU_PREINIT_RUNNER_BIN
#endif
	.global ksu_preinit_runner_end
ksu_preinit_runner_end:
