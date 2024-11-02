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

KPM_NAME("kpm-syscall-hook-process_vm_readv");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module process_vm_readv Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

void before_process_vm_readv(hook_fargs6_t *args, void *udata)
{
    pid_t pid = (pid_t)syscall_argn(args, 0);
    const struct iovec *local_iov = (const struct iovec *)syscall_argn(args, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(args, 2);
    const struct iovec *remote_iov = (const struct iovec *)syscall_argn(args, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(args, 4);
    unsigned long flags = (unsigned long)syscall_argn(args, 5);

    struct task_struct *task = current;

    pr_info("process_vm_readv called by task: %llx, pid: %d, liovcnt: %lu, riovcnt: %lu, flags: %lu\n",
            task, pid, liovcnt, riovcnt, flags);
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    pr_info("kpm-syscall-hook-process_vm_readv init ..., args: %s\n", margs);

    if (!margs) {
        pr_warn("no args specified, skip hook\n");
        return 0;
    }

    hook_err_t err = HOOK_NO_ERR;

    if (!strcmp("function_pointer_hook", margs)) {
        pr_info("function pointer hook ...");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, 0, 0);
    } else if (!strcmp("inline_hook", margs)) {
        pr_info("inline hook ...");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, 0, 0);
    } else {
        pr_warn("unknown args: %s\n", margs);
        return 0;
    }

    if (err) {
        pr_err("hook process_vm_readv error: %d\n", err);
    } else {
        pr_info("hook process_vm_readv success\n");
    }
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    pr_info("kpm-syscall-hook-process_vm_readv exit ...\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscall(__NR_process_vm_readv, before_process_vm_readv, 0);
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscall(__NR_process_vm_readv, before_process_vm_readv, 0);
    }
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_EXIT(syscall_hook_demo_exit);
