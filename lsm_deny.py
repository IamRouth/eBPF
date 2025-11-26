#!/usr/bin/python3
from bcc import BPF, libbcc
import os
import sys
import ctypes

# ================= USER CONFIGURATION =================
# 1. The ID of the user you want to restrict.
#    Run `id -u <username>` in a terminal to find this.
#    WARNING: Do NOT use your own UID (usually 1000) or 0 (root).
TARGET_UID = 1003

# 2. Denylist:
#    This user will NOT be able to open files with these names (basename).
#    All other files are allowed.
FORBIDDEN_FILES = [
    b"secret.txt",
    b"main.py",
]
# ======================================================

# ================= BPF C CODE =========================
bpf_source = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno-base.h>

struct key_t {
    char name[64];
};

// Hash map to store 'Forbidden' filenames (denylist)
BPF_HASH(denylist, struct key_t, u8, 256);

// LSM hook: file_open
LSM_PROBE(file_open, struct file *file) {
    u32 uid = bpf_get_current_uid_gid();

    // Only restrict the target UID
    if (uid != %d) {
        return 0;
    }

    // Get filename basename from dentry
    struct dentry *dentry = file->f_path.dentry;
    struct key_t key = {};
    bpf_probe_read_kernel_str(&key.name, sizeof(key.name), dentry->d_name.name);

    // Look up in denylist
    u8 *val = denylist.lookup(&key);
    if (val) {
        // File is forbidden
        bpf_trace_printk("Denied access to forbidden file: %%s\\n", key.name);
        return -EPERM;
    }

    // Everything else is allowed
    return 0;
}
""" % TARGET_UID
# ======================================================


def main():
    # Safety Check: Must be root
    if os.geteuid() != 0:
        print("[-] Error: This script must be run as Root (sudo).")
        sys.exit(1)

    print(f"[*] Compiling eBPF LSM program...")
    print(f"[*] Deny-listing for UID: {TARGET_UID}")

    # 1. Compile and Load BPF
    try:
        b = BPF(text=bpf_source)
    except Exception as e:
        print("[-] Compilation Failed!")
        print("    Ensure your Kernel is 5.7+ and compiled with CONFIG_BPF_LSM=y")
        print(f"    Error details: {e}")
        sys.exit(1)

    # 2. Populate the Map (The Denylist)
    print("[*] Populating Denylist Map in Kernel...")
    deny_map = b.get_table("denylist")

    for name in FORBIDDEN_FILES:
        key = deny_map.Key()
        safe_name = name[:63]  # truncate to fit struct key_t.name[64]
        key.name = safe_name
        deny_map[key] = ctypes.c_uint8(1)
        print(f"    - Forbidden: {safe_name.decode('utf-8')}")

    # 3. Attach the LSM Hook
    print("[*] Attaching LSM Hook to 'file_open'...")
    try:
        # BCC names the LSM program as lsm__file_open for LSM_PROBE(file_open, ...)
        func = b.load_func("lsm__file_open", BPF.LSM)
        libbcc.lib.bpf_attach_lsm(func.fd)
    except Exception as e:
        print("[-] Attachment Failed!")
        print("    Check: cat /sys/kernel/security/lsm (should contain 'bpf')")
        print(f"    Error: {e}")
        print("    Available functions in BPF object:", [k for k in b.funcs.keys()])
        sys.exit(1)

    print("\n[+] SUCCESS: Denylist LSM Active!")
    print(f"[+] User {TARGET_UID} can do everything EXCEPT open files in the denylist.")
    print("[+] Check this terminal for 'Denied access to forbidden file' messages.")
    print("[!] Press Ctrl+C to stop.\n")

    # 4. Monitoring Loop: print bpf_trace_printk output
    try:
        while True:
            try:
                (task, pid, cpu, flags, ts, msg) = b.trace_fields()
                print(f"[LSM] PID: {pid} | {msg.decode('utf-8')}", end='')
            except ValueError:
                continue
    except KeyboardInterrupt:
        print("\n[*] Detaching and Exiting...")
        sys.exit(0)


if __name__ == "__main__":
    main()
