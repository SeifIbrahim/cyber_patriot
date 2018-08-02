#Ubuntu Checklist
#Note: All of the following commands can be typed into the terminal, which can be accessed with the key combination: CTRL+ALT+T or found by searching in the Dash Home. Some may not work on some Linux systems, therefore, if some commands don’t work, skip them.

#Permission Elevation:
#sudo su  elevates you to root privileges (you may have to provide your password)
if [[ $EUID -ne 0 ]]
then
  echo "You must be root to run this script."
  exit 1
fi
#Start Uncomplicated Firewall:
sudo ufw enable # enables uncomplicated firewall
sudo service ufw start # starts uncomplicated firewall
sudo apt-get -y install gufw # installs another type of firewall
sudo apt-get -y install firestarter # installs another type of firewall
#Install Nec -yessary Services:
sudo apt-get -y install nmap # installs nmap, which is used to identify open ports and services associated with them
sudo apt-get -y install htop # installs htop, which can be used to monitor services
sudo apt-get -y install slay # installs slay, which can be used to log off malicious users
sudo apt-get -y install libpam-cracklib # installs cracklib, which can be used to set password policies
sudo apt-get -y install sysv-rc-conf # installs sysv-rc-conf, which can be used to monitor and configure run levels of services
sudo apt-get -y install clamav # installs clamav, an antivirus program for linux
sudo apt-get -y install snort # installs snort, another antivirus
sudo apt-get -y install john # installs john, a password cracking tool
sudo apt-get -y install bastille # after installation finishes, type: “bastille -c”, this will allow you to accept license agreement so you can use it
sudo apt-get -y install apparmor-profiles # type apparmor_status to use.

#Uninstall Unnecessary Services:
#If the following services are not required to be on the system, then uninstall them as follows:
#First, search for them:
#nmap localhost >> this command shows all services running on open ports
#sudo service --status-all >> shows all services running, look for unnecessary ones.
sudo apt-get -y purge vsftpd ftp netcat samba finger ssh apache2 mysql rstatd talk ntalk rexec rlogin rsh bind9
#sudo apt-get purge [package name] >> use to delete anything that these searches come up with

#Process Monitoring: TODO
#htop >> lets you monitor all services currently running on a system.

#Services: TODO
#sudo gedit /etc/inetd.conf >> shows all services running and if you want to disable one, put a hashtag at the beginning of the line it’s on.
#cd /etc/xinetd.d >> when you open this directory, look at the documents in it, they will be named as the services that are running on your computer, such as telnet. If you open one of the documents, you will the find the line: “disable = yes/no” in which either yes or no will be there. Change the yes or no depending on if you would like to disable the service or not. I recommend to disable everything unless there is something like “ufw” or “clamav” or another type of firewall or antivirus database.

#Run Levels: TODO
#sysv-rc-conf >> launches sysv-rc-conf, in which you can configure run levels of various services such as firewall and nmap, but it only works if you have already installed sysv-rc-conf to the terminal.
#Start Up Services: TODO
#cd /etc/rc2.d >> look at services and evaluate which ones you don’t want there. When you decide, to delete them, type this: “sudo rm /etc/rc2.d/[filename]”.
#cd /etc/rc3.d >> look at services and evaluate which ones you don’t want there. When you decide, to delete them, type this: “sudo rm /etc/rc3.d/[filename]”.
#Install Latest Updates:
sudo apt-get update # updates your computer
sudo apt-get upgrade # updates all packages on system (may take a very long time)
#Lock Unnecessary Accounts:
sudo passwd -l root # locks root account (good security practice)
sudo passwd -l bin # locks bin account (also a good security practice)
sudo passwd -l sys # locks sys account (also a good security practice)
sudo passwd -l uucp # locks uucp account (also a good security practice)
#Securing the Apache2 Web Server: TODO
#If apache2 is a package that is required to be on the system, then secure it as follows:
#cd /var/www >> takes you to apache directory, type “ls” and explore. If you would like to view a document that you see, type “sudo gedit [name of document]”. If you would like to view a directory within this directory, type “cd [directory name]”. If you would like to delete a suspicious file, type “sudo rm [document name]”.
#Securing SSH:
#If ssh is a package that is required to be on the system, then secure it as follows:
echo -n "OpenSSH Server [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  sudo apt-get -y install openssh-server
  # Disable root login
  sudo sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
  sudo sed -i '/^protocol/ c\protocol 2' /etc/ssh/sshd_config
  sudo sed -i '/^PermitEmptyPasswords/ c\PermitEmptyPasswords no' /etc/ssh/sshd_config
  sudo sed -i '/^Banner/ c\Banner /etc/issue' /etc/ssh/sshd_config
  sudo sed -i '/^IgnoreRhosts/ c\IgnoreRhosts yes' /etc/ssh/sshd_config
  sudo sed -i '/^RhostsAuthentication/ c\RhostsAuthentication no' /etc/ssh/sshd_config
  sudo sed -i '/^RhostsRSAAuthentication/ c\RhostsRSAAuthentication no' /etc/ssh/sshd_config
  sudo sed -i '/^HostbasedAuthentication/ c\HostbasedAuthentication no' /etc/ssh/sshd_config
  sudo sed -i '/^LoginGraceTime/ c\LoginGraceTime 1m' /etc/ssh/sshd_config
  sudo sed -i '/^SyslogFacility/ c\SyslogFacility AUTH' /etc/ssh/sshd_config
  sudo sed -i '/^MaxStartups/ c\MaxStartups 10' /etc/ssh/sshd_config
  sudo service ssh restart
else
  sudo apt-get -y purge openssh-server*
fi
#sudo gedit /etc/ssh/sshd_config >> inside this document, set the following values to these variables, you may have to do some searching as they are scattered about:
#Protocol 2
#PermitRootLogin no
#PermitEmptyPasswords no
#Banner /etc/issue
#IgnoreRhosts yes
#RhostsAuthentication no
#RhostsRSAAuthentication no
#HostbasedAuthentication no
#LoginGraceTime 1m (or less – default is 2 minutes)
#SyslogFacility AUTH (provides logging under syslog AUTH)
#AllowUser (list of users allowed access) TODO
#DenyUser (list of system accounts and others not allowed) TODO
#MaxStartups 10 (or less – use 1/3 the total number of remote users)
#Make sure that after you make these changes that you go back to terminal and type this:
#“sudo service ssh restart”
#This is so that the new settings can be saved.
#sudo gedit /etc/hosts.allow >> shows hosts that are allowed to log into the system, check cor malicious hosts TODO
#sudo gedit /etc/hosts.deny >> shows hosts that are not allowed to log in to the system, add the names of malicious hosts that you found in hosts.allow TODO
#Local Security Policies:
#This will only work if you install libpam-cracklib.
#sudo gedit /etc/pam.d/common-auth >> Add the line: auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent
#sudo gedit /etc/pam.d/common-password >> Add the line: password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1
#Right under that line, add this one: password requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root
#Right under that line, add this one: password [success=1 default=ignore] pam_unix.so obscure use_authtok sha512 shadow
#sudo gedit /etc/pam.d/systemauth >> Add this line: auth required /lib/security/$ISA/pam_tally.so no_magic_root account required /lib/security/$ISA/pam_tally.so per_user deny=5 no_magic_root reset
sudo sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth
sudo sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n password requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root\n password [success=1 default=ignore] pam_unix.so obscure use_authtok sha512 shadow/' /etc/pam.d/common-password
sudo sed -i '1 s/^/auth required /lib/security/$ISA/pam_tally.so no_magic_root account required /lib/security/$ISA/pam_tally.so per_user deny=5 no_magic_root reset\n/' /etc/pam.d/systemauth
#sudo gedit /etc/login.defs >> press key combination CTRL+F and find the word max. When you find it, set the following parameters:                             password [success=1 default=ignore] pam_unix.so obscure use_authtok sha512 shadow
#PASS_MAX_DAYS   30
#PASS_MIN_DAYS   3
#PASS_MIN_LEN   8
#PASS_WARN_AGE   25
  
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS 30' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS 3'  /etc/login.defs
sudo sed -i '/^PASS_MIN_LEN/ c\PASS_MIN_LEN 8'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE 25' /etc/login.defs
   
#Internet Security:
#sudo gedit /etc/hosts >> look for possibly malicious website rerouting and put hashtags at the beginning of suspicious lines of code. There will be a bunch of website names with their IP numbers on the side. To test one out, copy the IP address and put it into a search engine like Firefox. If it takes you to the wrong website, then it’s bad. But be careful, it could be a fake version of a website too. TODO
#sudo gedit /etc/resolv.conf >> change the nameserver to 8.8.8.8, Google’s DNS.
sudo sed -i '/^nameserver/ c\nameserver 8.8.8.8' /etc/resolv.conf
#Scheduled Tasks and Permissions:
#sudo crontab -e >> put a hashtag at the beginning of all lines of the document unless one looks like it is useful or necessary. TODO
#sudo gedit /etc/crontab >> look for malicious tasks and put hashtags at the beginning of lines containing the task to disable it. TODO
#cd /etc/cron.* >> search around directory and use gedit to open files and cd to open a new directory. TODO
#cd /var/spool/cron/crontabs >> put a hashtag at the beginning of all lines in the document that don’t already have one there, unless a task on a line looks important or necessary. TODO
#In order to limit access to cron, type these commands into terminal:
/bin/rm -f /etc/cron.deny /etc/at.deny
echo root > /etc/cron.allow
echo root > /etc/at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow
#sudo visudo >> look for malicious users under root, admin, and user permissions and put hashtags at the beginnings of lines containing their names TODO

#Guest Account:
#sudo gedit /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf >> Add this line: allow-guest=false
sudo sed -i '/^allow-guest/ c\allow-guest=false' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
#Users and Groups: TODO
#sudo gedit /etc/group >> this document displays all of the groups that can use the computer, put hashtags at the beginnings of lines containing the names of possibly malicious groups.
#sudo gedit /etc/passwd >> put hashtags at the beginnings of lines containing the names of possible malicious users
#sudo gedit /etc/shadow >> put hashtags at the beginnings of lines containing the names of possibly malicious users and after you are done, type “sudo passwd -l [username]” for every malicious user that you found in the /etc/passwd and /etc/shadow files.
sudo chmod 400 /etc/shadow # disables access to shadow by normal users
sudo chown root:root /etc/shadow # sets ownership for shadow

#Startup:
#cd /etc/init.d >> shows startup files, look for malicious ones and remove them with: sudo rm [filename]. TODO
#sudo gedit /etc/rc.local >> if there are any lines without a hashtag at the beginnings of them except for exit 0, then put a hashtag at the beginnings of them, too.
sed -i '/exit 0/!s/^/#/' /etc/rc.local
#Setting Appropriate Permissions:
sudo chmod 0700 /etc/profile # sets permissions for /etc/profile
sudo chmod 0700 /etc/hosts.allow # sets permissions for hosts file
sudo chmod 0700 /etc/mtab # sets permissions for mtab
sudo chmod 0700 /etc/utmp # sets permissions for utmp
sudo chmod 644 /etc/fstab # sets permissions for fstab
sudo chmod 644 /etc/passwd # sets permissions for passwd file
sudo chmod 644 /etc/group # sets permissions for group
sudo chmod 644 /etc/sudoers # sets permissions for sudoers file
sudo chown root:root /etc/fstab # sets ownership for fstab
sudo chown root:root /etc/passwd # sets ownership for passwd file sudo chown root:root /etc/group # sets ownership for group file
sudo chown root:root /etc/sudoers # sets ownership for visudo
sudo chmod 02750 /bin/su # sets appropriate permissions for su
sudo chmod 02750 /bin/sudo # sets appropriate permissions for sudo
sudo chmod 02750 /bin/ping # sets appropriate permissions for ping
sudo chmod 02750 /sbin/ifconfig # sets appropriate permissions for ifconfig
sudo chmod 02750 /usr/bin/w # sets permissions for users
sudo chmod 02750 /usr/bin/who # sets permissions for users
sudo chmod 02750 /usr/bin/locate # sets permissions for locate
sudo chmod 02750 /usr/bin/whereis # sets permissions for whereis
#find / -type d -perm +2 -ls >> finds world writeable files, for each of which you should type: “sudo chmod 750 [filename]” to give them correct permissions TODO
  
#Passwords: TODO
#sudo passwd [user] >> changes password for requested user, change for all users to secure passwords. Make sure to give root a secure password by typing: “sudo passwd root”.
#Update Manager: TODO
#Update Manager can never be found in exactly the same place in all systems, so do some searching and it may come up. Then click Settings and click Updates. Set the following settings:
#Important Security Updates: Check the box.
#Recommended Updates: Check the box.
#Automatically check for updates: Daily
#When there are security updates: Display Immediately
#When there are other updates: Display Immediately
#On some versions of Ubuntu, these are not the settings to be configured. If some of these are not here, then just configure the settings so that everything related to updates is done immediately and automatically.

#Device Security:
sudo chmod 0640 /dev/null # sets appropriate permissions for device file
sudo chmod 0640 /dev/tty # sets appropriate permissions for device file
sudo chmod 0640 /dev/console # sets appropriate permissions for device file

#Home Directory:
sudo chmod 0750 /home/* # do this for all users
#Managing Applications:
#Applications à Ubuntu Software Center à Installed Software. Check for unnecessary applications and remove them.

#Log Files:
#/var/log/messages >> General log messages
#/var/log/boot >> System boot log
#/var/log/debug >> Debugging log messages
#/var/log/auth.log >> User login and authentication logs
#/var/log/daemon.log >> Running services such as squid, ntpd and others log message to this file
#/var/log/kern.log >> Kernel log file
#Other Things:
#sudo gedit /etc/syslog.conf >> opens syslog.conf file, which shows you some things are being logged. Make sure there are no logs that are being disabled and that everything looks normal. TODO
sudo chmod 600 /var/adm/loginlog # sets permissions for loginlog
sudo chown root:groupsys /var/adm/loginlog # sets ownership for loginlog
#Last Actions:
#If you have some time to spare, look through users’ home files, if you can find them, and keep an eye out for .mp3 files or other malicious files. One last command you might use in the terminal is: “find / | grep -i [text]” This finds a string of your choice and looks for it everywhere in the entire computer. So search for things like rootkit or Trojan and maybe you’ll find something. Go secure another computer!

sudo apt-get -y purge hydra* john* nikto* netcat*
for suffix in mp3 txt wav wma aac mp4 mov avi gif jpg png bmp img exe msi bat sh
do
  sudo find /home -name *.$suffix
done
