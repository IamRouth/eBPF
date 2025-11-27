# 🔒 eBPF LSM File-Access Denylist for Specific User

A lightweight Linux Security Module (LSM) using eBPF to restrict a specific user from opening specific files, enforced inside the kernel using the `file_open` LSM hook.

This project demonstrates how to attach an eBPF LSM probe that blocks opening certain filenames (denylist) only for a target UID.

## ⚙️ Features

* **Basename Filtering:** Deny file opening based on the filename (basename) only.
* **Targeted Restriction:** Restriction applies only to one specific user UID.
* **LSM Hook:** Implemented using the `file_open` Linux Security Module hook.
* **Kernel Enforcement:** Logic runs in kernel space, not as a userspace interceptor.
* **Live Logging:** Logs denied attempts via `bpf_trace_printk`.

---

## 📌 Requirements

### 1. Kernel Configuration
You must have a Linux kernel (Version ≥ 5.7) with BPF LSM enabled.

Check your config:
```bash
cat /sys/kernel/security/lsm
```
# Output must include 'bpf'

```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
```
# Output must be: CONFIG_BPF_LSM=y


## ✔ Install Dependencies

You must have the BPF Compiler Collection (BCC) tools and Linux headers installed.

```bash
sudo apt update
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

## 👤 Create Restricted User
```bash
sudo adduser restricted_user
id -u restricted_user
```

## Note: Take note of the UID returned by the id command. You must update the TARGET_UID variable inside the script to match this number:

```bash
TARGET_UID = 1003
```

## 🛠 Enable eBPF LSM in GRUB

1. Open GRUB config:

```bash 
sudo nano /etc/default/grub
```

2. Modify:
```bash
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=bpf"
```

3. Update & reboot:
```bash 
sudo update-grub

sudo reboot
```

## ▶️ Run the LSM Program
1. Terminal 1 (root)
```bash
sudo python3 lsm_deny.py
```

 If successful, you will see:
 
```bash
[+] SUCCESS: Denylist LSM Active!
User <UID> can do everything EXCEPT forbidden files.
```

2. 🧪 TESTING (IMPORTANT)
   Terminal 2

  Switch to restricted user:

```bash
su restricted_user
```

 Try accessing forbidden file:
```bash
cat secret.txt
```


Expected behavior:
```bash
❌ Access denied
```
Terminal 1 will show:
```bash
[LSM] Denied access to forbidden file: secret.txt
```

3. 🛑 Stopping the LSM Program

The LSM is detached automatically when you press:
```bash
Ctrl + C
```


If the first terminal is stopped, the restrictions stop immediately.

📁 Forbidden File List

Inside the script:

```bash
FORBIDDEN_FILES = [
    b"secret.txt",
    b"main.py",
]
```


Add/remove filenames (basename only).

