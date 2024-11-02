/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/current.h>

// Make sure KPM_NAME_LEN is large enough for your module name
#define KPM_NAME_LEN 64  // Adjust this as needed based on your module name length

// Ensure the info string length is less than or equal to KPM_NAME_LEN
KPM_NAME("kpm-syscall-hook-process_vm_readv");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module process_vm_readv Hook Example");

// Forward declaration of the hook types and functions
typedef struct hook_fargs6 { /* Define this structure */ } hook_fargs6_t;
typedef int hook_err_t; // Define this type according to your library's specification

void before_process_vm_readv(hook_fargs6_t *args, void *udata);

static long syscall_hook_init(const char *args, const char *event, void __user *reserved);
static long syscall_hook_exit(void __user *reserved);

void before_process_vm_readv(hook_fargs6_t *args, void *udata)
{
    pid_t pid = (pid_t)syscall_argn(args, 0);
    const struct iovec *local_iov = (const struct iovec *)syscall_argn(args, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(args, 2);
    const struct iovec *remote_iov = (const struct iovec *)syscall_argn(args, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(args, 4);
    unsigned long flags = (unsigned long)syscall_argn(args, 5);

    pr_info("process_vm_readv called by pid: %d, liovcnt: %lu, riovcnt: %lu, flags: %lu\n",
            pid, liovcnt, riovcnt, flags);

    // Log base address and length of each remote iovec entry
    for (unsigned long i = 0; i < riovcnt; i++) {
        struct iovec iov_entry;
        if (copy_from_user(&iov_entry, &remote_iov[i], sizeof(struct iovec)) == 0) {
            pr_info("remote_iov[%lu]: iov_base = %p, iov_len = %zu\n", i, iov_entry.iov_base, iov_entry.iov_len);
        } else {
            pr_warn("Failed to copy iovec entry from user space\n");
        }
    }
}

static long syscall_hook_init(const char *args, const char *event, void __user *reserved)
{
    pr_info("Initializing syscall hook for process_vm_readv\n");

    hook_err_t err = fp_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, 0, 0);
    if (err) {
        pr_err("Failed to hook process_vm_readv: error %d\n", err);
        return -1;
    }

    pr_info("process_vm_readv hook installed successfully\n");
    return 0;
}

static long syscall_hook_exit(void __user *reserved)
{
    pr_info("Removing syscall hook for process_vm_readv\n");

    fp_unhook_syscall(__NR_process_vm_readv, before_process_vm_readv, 0);
    pr_info("process_vm_readv hook removed successfully\n");
    return 0;
}

KPM_INIT(syscall_hook_init);
KPM_EXIT(syscall_hook_exit);
