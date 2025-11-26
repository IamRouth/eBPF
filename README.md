sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
  

sudo adduser restricted_user
   id -u restricted_user 

  TARGET_UID = 1001 # Replace with the actual UID of your test user


sudo nano /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,capability,landlock,yama,apparmor,bpf"

sudo update-grub

sudo reboot

cat /sys/kernel/security/lsm
