🔒 eBPF LSM File-Access Denylist for Specific User

A lightweight Linux Security Module (LSM) using eBPF to restrict a specific user from opening specific files, enforced inside the kernel using the file_open LSM hook.

This project demonstrates how to attach an eBPF LSM probe that blocks opening certain filenames (denylist) only for a target UID.

⚙️ Features

Deny file opening based on basename only

Restriction applies only to one specific user UID

Implemented using the LSM (Linux Security Module) eBPF hook

Kernel-level enforcement (not a userspace interceptor)

Logs denied attempts via bpf_trace_printk

📌 Requirements
✔ Kernel

You must have a kernel with:

CONFIG_BPF_LSM=y

Version ≥ 5.7

Check:

cat /sys/kernel/security/lsm
grep CONFIG_BPF_LSM /boot/config-$(uname -r)


bpf must appear in the LSM list.

✔ Install Dependencies
sudo apt update
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

👤 Create Restricted User
sudo adduser restricted_user
id -u restricted_user


Use this UID inside the script:

TARGET_UID = 1003

🛠 Enable eBPF LSM in GRUB

Open GRUB config:

sudo nano /etc/default/grub


Modify:

GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=bpf"


Update & reboot:

sudo update-grub
sudo reboot

▶️ Run the LSM Program
Terminal 1 (root)
sudo python3 lsm_deny.py


If successful, you will see:

[+] SUCCESS: Denylist LSM Active!
User <UID> can do everything EXCEPT forbidden files.

🧪 TESTING (IMPORTANT)
Terminal 2

Switch to restricted user:

su restricted_user


Try accessing forbidden file:

cat secret.txt


Expected behavior:

❌ Access denied
Terminal 1 will show:

[LSM] Denied access to forbidden file: secret.txt

🛑 Stopping the LSM Program

The LSM is detached automatically when you press:

Ctrl + C


If the first terminal is stopped, the restrictions stop immediately.

📁 Forbidden File List

Inside the script:

FORBIDDEN_FILES = [
    b"secret.txt",
    b"main.py",
]


Add/remove filenames (basename only).

🧠 How It Works
🔹 eBPF Program (C)

Hooks into file_open LSM path

Checks UID

Extracts the basename of file (dentry->d_name.name)

Looks up in eBPF hash map (denylist)

Returns -EPERM if matched

🔹 Python Loader

Loads & compiles the eBPF C code

Populates denylist map

Attaches to LSM hook using bpf_attach_lsm

Prints trace logs in real time

🪪 Security Notes
❗ This does not persist across reboots

You must run the script again after reboot.

❗ If the root terminal running the script stops

Restrictions disappear immediately.

✔ Safe for experimentation

Nothing is permanently altered in your kernel.

📄 Full Source Code

The complete script is included in this repository:

lsm_deny.py
