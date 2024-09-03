package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	printBanner()
	fmt.Println("Select your environment:")
	fmt.Println("1. Windows CMD")
	fmt.Println("2. Linux Shell")
	fmt.Println("3. PowerShell")

	choice := getUserInput("Enter your choice (1/2/3): ")

	switch choice {
	case "1":
		displayWindowsCmdOptions()
	case "2":
		displayLinuxCmdOptions()
	case "3":
		displayPowershellCmdOptions()
	default:
		fmt.Println("Invalid choice.")
	}
}

func printBanner() {
	fmt.Println("███╗   ███╗███████╗██╗  ██╗")
	fmt.Println("████╗ ████║██╔════╝██║  ██║")
	fmt.Println("██╔████╔██║█████╗  ███████║")
	fmt.Println("██║╚██╔╝██║██╔══╝  ██╔══██║")
	fmt.Println("██║ ╚═╝ ██║███████╗██║  ██║")
	fmt.Println("╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝")
	fmt.Println()
	fmt.Println("        Created by A.M Pachouri")
	fmt.Println("        YouTube        -- @mastersinethicalhacking")
	fmt.Println("        Instagram      -- @mastersinethicalhacking")
	fmt.Println("        Facebook       -- MastersInEthicalHacking")
	fmt.Println()
}

func getUserInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return input[:len(input)-1]
}

func displayWindowsCmdOptions() {
	fmt.Println("\nSelected: Windows CMD")
	displayCategoryOptions("Windows CMD")
}

func displayLinuxCmdOptions() {
	fmt.Println("\nSelected: Linux Shell")
	displayCategoryOptions("Linux Shell")
}

func displayPowershellCmdOptions() {
	fmt.Println("\nSelected: PowerShell")
	displayCategoryOptions("PowerShell")
}

func displayCategoryOptions(env string) {
	fmt.Println("Select a category:")
	fmt.Println("1. System Commands")
	fmt.Println("2. User and Group Handling")
	fmt.Println("3. Network Management")
	fmt.Println("4. File System and Disk Management")
	fmt.Println("5. Security and Access Control")
	fmt.Println("6. Backup and Restore")
	fmt.Println("7. Remote Commands")
	fmt.Println("8. Exit")

	choice := getUserInput("Enter your choice (1/2/3/4/5/6/7/8): ")

	switch choice {
	case "1":
		displaySystemCommands(env)
	case "2":
		displayUserGroupCommands(env)
	case "3":
		displayNetworkCommands(env)
	case "4":
		displayFileSystemDiskCommands(env)
	case "5":
		displaySecurityCommands(env)
	case "6":
		displayBackupRestoreCommands(env)
	case "7":
		displayRemoteCommands(env)
	case "8":
		fmt.Println("Exiting...")
		return
	default:
		fmt.Println("Invalid choice.")
	}
}

func displaySystemCommands(env string) {
	fmt.Println("\nSystem Commands:")
	switch env {
	case "Windows CMD":
		fmt.Println(`**System Commands**
   -  systeminfo ==> Display detailed configuration information about the computer and its operating system.
   -  tasklist ==> Display a list of all running processes.
   -  taskkill /PID pid ==> Terminate a process by its PID.
   -  shutdown /s /t 0 ==> Shut down the computer immediately.
   -  shutdown /r /t 0 ==> Restart the computer immediately.
   -  chkdsk ==> Check a disk and display a status report.
   -  sfc /scannow ==> Scan and repair system files.
   -  wmic ==> Windows Management Instrumentation Command-line tool.
   -  echo %username% ==> Display the current username.
   -  ver ==> Display the Windows version.
   -  dir ==> List the contents of a directory.
   -  cls ==> Clear the command prompt screen.
   -  date ==> Display or set the date.
   -  time ==> Display or set the time.
   -  taskmgr ==> Open the Task Manager.
   -  eventvwr ==> Open the Event Viewer.
   -  msconfig ==> Open the System Configuration utility.
   -  diskpart ==> Open the Disk Partition utility.
   -  driverquery ==> Display a list of all installed drivers.
   -  sc config servicename ==> Configure a service (e.g., start, stop).
   -  fsutil ==> Perform tasks related to file systems, such as managing volumes, quotas, and more.\n**System Information and Performance**
   -  systeminfo ==> Display detailed system configuration information.
   -  tasklist ==> Display a list of running processes.
   -  taskkill /im processname ==> Terminate a process by its name.
   -  perfmon ==> Open the Performance Monitor utility.
   -  msinfo32 ==> Open the System Information utility.
   -  powercfg /a ==> Display the power-saving states available on the computer.
   -  powercfg /h on ==> Enable hibernation.
   -  powercfg /batteryreport ==> Generate a battery health report.
   -  driverquery ==> Display a list of installed drivers.
   -  query user ==> Display information about logged-in users.
   -  systempropertiesperformance ==> Open the Performance Options window.
   -  resmon ==> Open the Resource Monitor.
`)
	case "Linux Shell":
		fmt.Println(`**System Commands**
   -  uname -a ==> Show system and kernel information.
   -  top ==> Display system tasks and resource usage.
   -  htop ==> Interactive process viewer (requires installation).
   -  ps aux ==> Display all running processes.
   -  kill PID ==> Terminate a process by its PID.
   -  killall ProcessName ==> Terminate all processes with the specified name.
   -  df -h ==> Show disk usage of filesystems.
   -  du -sh /path/to/directory ==> Display disk usage of a directory.
   -  free -h ==> Show memory usage.
   -  uptime ==> Show how long the system has been running.
   -  reboot ==> Restart the system.
   -  shutdown -h now ==> Shut down the system immediately.
   -  shutdown -r now ==> Reboot the system immediately.
   -  dmesg ==> Print kernel ring buffer messages.
   -  lsblk ==> List information about block devices.
   -  mount /dev/sdX /mnt ==> Mount a filesystem.
   -  umount /mnt ==> Unmount a filesystem.
   -  fdisk -l ==> List disk partitions.
   -  blkid ==> Display block device attributes.
   -  iostat ==> Report CPU and I/O statistics.
   -  sar ==> Collect, report, or save system activity information.
   -  systemctl status ==> Show status of a service.
   -  journalctl -xe ==> View system logs.
   -  service servicename start/stop/restart ==> Start, stop, or restart a service.
\n**System Information**
   -  uname -a ==> Show system information.
   -  hostnamectl ==> Show or set the system hostname.
   -  lsb_release -a ==> Display distribution-specific information.
   -  cat /etc/os-release ==> Display OS release information.
   -  arch ==> Display the machine architecture.
   -  lscpu ==> Display CPU architecture information.
   -  lsusb ==> List USB devices.
   -  lspci ==> List PCI devices.
   -  dmidecode ==> Dump BIOS and hardware information.
   -  free -m ==> Display memory usage in megabytes.
   -  df -h ==> Display disk usage.
   -  uptime ==> Show system uptime.
   -  dmesg ==> Print kernel ring buffer messages.
   -  lsmod ==> Show the status of modules in the Linux Kernel.\n**Log Management**
   -  journalctl ==> Query and display messages from the systemd journal.
   -  journalctl -u servicename ==> View logs for a specific service.
   -  tail -f /var/log/syslog ==> Monitor system logs in real-time.
   -  logrotate ==> Manage the rotation of log files.
   -  dmesg | less ==> View kernel messages.
   -  last ==> Show last logins of users.
   -  lastb ==> Show bad login attempts.
   -  who /var/log/wtmp ==> Display who has logged in.
\n**Development Tools**
   -  gcc file.c -o output ==> Compile a C program.
   -  g++ file.cpp -o output ==> Compile a C++ program.
   -  make ==> Build and manage projects.
   -  git clone URL ==> Clone a Git repository.
   -  git commit -m "message" ==> Commit changes to a Git repository.
   -  git push origin branch ==> Push changes to a remote repository.
   -  python script.py ==> Run a Python script.
   -  pip install package ==> Install a Python package.
   -  java -jar file.jar ==> Run a Java application.
   -  perl script.pl ==> Run a Perl script.
   -  ruby script.rb ==> Run a Ruby script.\n**Process Management**
   -  ps aux ==> Display all running processes.
   -  top ==> Display dynamic real-time view of running processes.
   -  htop ==> Interactive process viewer.
   -  kill PID ==> Kill a process by its PID.
   -  killall processname ==> Kill all processes with the specified name.
   -  pkill processname ==> Kill processes by name.
   -  bg ==> Resume a suspended job in the background.
   -  fg ==> Bring a background job to the foreground.
   -  jobs ==> List active jobs.
   -  nice -n 10 command ==> Run a command with a specified niceness.
   -  renice -n 10 PID ==> Change the niceness of an existing process.`)
		
	case "PowerShell":
		fmt.Println(`**System Commands**
   -  Get-ComputerInfo ==> Retrieve detailed information about the computer's system configuration.
   -  Get-Process ==> Display a list of running processes.
   -  Stop-Process -Name processname ==> Terminate a process by its name.
   -  Restart-Computer ==> Restart the computer.
   -  Shutdown-Computer ==> Shut down the computer.
   -  Get-Service ==> Display the status of services on the computer.
   -  Start-Service -Name servicename ==> Start a service.
   -  Stop-Service -Name servicename ==> Stop a service.
   -  Restart-Service -Name servicename ==> Restart a service.
   -  Get-EventLog -LogName Application ==> Retrieve entries from the event log.
   -  Clear-EventLog -LogName Application ==> Clear the event log.
   -  Test-Connection -ComputerName hostname ==> Test network connectivity to a computer (similar to ping).
   -  Set-TimeZone -Name "Time Zone" ==> Set the time zone on the computer.
   -  Get-WmiObject -Class Win32_OperatingSystem ==> Retrieve information about the operating system.
   -  Get-Disk ==> Display information about disk drives.
   -  Get-Volume ==> Display information about volumes.
   -  New-Item -Path "path" -ItemType "directory" ==> Create a new directory.
   -  Remove-Item -Path "path" ==> Delete a file or directory.
   -  Rename-Item -Path "oldname" -NewName "newname" ==> Rename a file or directory.
   -  Copy-Item -Path "source" -Destination "destination" ==> Copy files or directories.
   -  Move-Item -Path "source" -Destination "destination" ==> Move files or directories.
   -  Clear-Host ==> Clear the PowerShell console screen.
`)
	}
}

func displayUserGroupCommands(env string) {
	fmt.Println("\nUser and Group Handling Commands:")
	switch env {
	case "Windows CMD":
		fmt.Println(`**User and Group Management**
   -  net user username /add ==> Add a new user.
   -  net user username /delete ==> Delete a user.
   -  net user ==> Display a list of all user accounts.
   -  net localgroup groupname /add username ==> Add a user to a group.
   -  net localgroup groupname /delete username ==> Remove a user from a group.
   -  net localgroup ==> Display a list of all groups.
   -  whoami ==> Display the current logged-in user.
   -  net accounts ==> Display or modify password and logon requirements.
   -  control userpasswords2 ==> Open the User Accounts dialog box.
   -  lusrmgr.msc ==> Open the Local Users and Groups management console.
   -  runas /user==>domain\username program ==> Run a program as another user.`)
	case "Linux Shell":
		fmt.Println(`**User and Group Management**
   -  adduser username ==> Add a new user.
   -  useradd username ==> Add a user (alternative command).
   -  userdel username ==> Delete a user.
   -  usermod -aG groupname username ==> Add a user to a group.
   -  groupadd groupname ==> Create a new group.
   -  groupdel groupname ==> Delete a group.
   -  passwd username ==> Change a user's password.
   -  chage -l username ==> Show user password expiration information.
   -  id username ==> Display user ID and group ID.
   -  who ==> Show who is logged on.
   -  w ==> Display who is logged in and what they are doing.
   -  last ==> Show last logins of users.
   -  su - username ==> Switch to another user.
   -  sudo command ==> Run a command as another user (typically root).
   -  visudo ==> Edit the sudoers file.
   -  chown user==>group file ==> Change ownership of a file.
   -  chmod 755 file ==> Change file permissions.
`)
	case "PowerShell":
		fmt.Println(`**User and Group Management**
   -  Get-LocalUser ==> List all local user accounts.
   -  New-LocalUser -Name "username" -Password (ConvertTo-SecureString "password" -AsPlainText -Force) ==> Create a new local user.
   -  Remove-LocalUser -Name "username" ==> Delete a local user.
   -  Get-LocalGroup ==> List all local groups.
   -  Add-LocalGroupMember -Group "groupname" -Member "username" ==> Add a user to a local group.
   -  Remove-LocalGroupMember -Group "groupname" -Member "username" ==> Remove a user from a local group.
   -  Get-LocalGroupMember -Group "groupname" ==> List all members of a local group.
   -  Set-LocalUser -Name "username" -PasswordNeverExpires $true ==> Set a user’s password to never expire.
   -  Enable-LocalUser -Name "username" ==> Enable a local user account.
   -  Disable-LocalUser -Name "username" ==> Disable a local user account.`)
	}
}

func displayNetworkCommands(env string) {
	fmt.Println("\nNetwork Management Commands:")
	switch env {
	case "Windows CMD":
		fmt.Println(`**Network Commands**
   -  ipconfig /all ==> Display all IP configuration information.
   -  ipconfig /release ==> Release the current IP address.
   -  ipconfig /renew ==> Renew the IP address.
   -  ping hostname ==> Send ICMP ECHO_REQUEST to a network host.
   -  tracert hostname ==> Trace the route to a network host.
   -  netstat -an ==> Display active TCP connections and listening ports.
   -  nslookup hostname ==> Query the DNS information for a domain.
   -  arp -a ==> Display the ARP table.
   -  route print ==> Display the IP routing table.
   -  netsh ==> Configure network settings (firewall, IP, interface, etc.).
   -  pathping hostname ==> Combine the features of ping and tracert.
   -  nbtstat -a hostname ==> Display NetBIOS over TCP/IP statistics.
   -  telnet hostname port ==> Connect to a remote machine using Telnet.
   -  net use ==> Connect to a shared resource.
   -  net share sharename=drive==>path ==> Create a network share.
   -  net session ==> Display or end a session with a remote computer.
   -  netsh wlan show profiles ==> Show saved wireless profiles.
   -  netsh int ip reset ==> Reset TCP/IP stack.
   -  hostname ==> Display the hostname of the computer.`)
	case "Linux Shell":
		fmt.Println(`**Network Commands**
   -  ifconfig ==> Display or configure a network interface.
   -  ip addr ==> Show IP addresses and properties.
   -  ping host ==> Send ICMP ECHO_REQUEST to network hosts.
   -  traceroute host ==> Trace the route packets take to the host.
   -  netstat -tuln ==> Show active listening ports.
   -  ss -tuln ==> Show active listening ports (alternative to netstat).
   -  nmap -sP 192.168.1.0/24 ==> Scan for live hosts in a network.
   -  dig domain ==> Query DNS information.
   -  nslookup domain ==> Query DNS information (alternative command).
   -  curl -I http==>//domain ==> Fetch HTTP headers from a URL.
   -  wget http==>//domain/file ==> Download a file from a URL.
   -  scp user@host==>/path/to/file /local/path ==> Secure copy a file from a remote host.
   -  ssh user@host ==> Connect to a remote host via SSH.
   -  iptables -L ==> List firewall rules.
   -  ip route ==> Show or manipulate the IP routing table.
   -  hostname -I ==> Display the IP address of the system.
   -  nmcli ==> Control NetworkManager from the command line.
   -  iwconfig ==> Show or manipulate wireless network interface.
   -  tcpdump -i eth0 ==> Capture network traffic on interface eth0.
   -  ethtool eth0 ==> Display or change ethernet device settings.\n**Package Management**
   -  apt update ==> Update the package index (Debian/Ubuntu).
   -  apt upgrade ==> Upgrade all packages (Debian/Ubuntu).
   -  apt install package ==> Install a package (Debian/Ubuntu).
   -  apt remove package ==> Remove a package (Debian/Ubuntu).
   -  apt search package ==> Search for a package (Debian/Ubuntu).
   -  yum update ==> Update all packages (RHEL/CentOS).
   -  yum install package ==> Install a package (RHEL/CentOS).
   -  yum remove package ==> Remove a package (RHEL/CentOS).
   -  dnf install package ==> Install a package (Fedora/RHEL8+).
   -  dnf remove package ==> Remove a package (Fedora/RHEL8+).
   -  rpm -i package.rpm ==> Install an RPM package.
   -  rpm -e package ==> Remove an RPM package.
   -  pacman -Syu ==> Update the system (Arch Linux).
   -  pacman -S package ==> Install a package (Arch Linux).
   -  pacman -R package ==> Remove a package (Arch Linux).
   -  snap install package ==> Install a snap package.
   -  snap remove package ==> Remove a snap package.
`)
	case "PowerShell":
		fmt.Println(`**Network Commands**
   -  Get-NetIPAddress ==> Display IP address configuration information.
   -  Get-NetIPConfiguration ==> Retrieve detailed network adapter configuration information.
   -  New-NetIPAddress -InterfaceAlias "interface" -IPAddress "ip address" -PrefixLength "subnet" ==> Assign a static IP address.
   -  Test-NetConnection -ComputerName hostname ==> Test the network connection to a remote host.
   -  Get-NetAdapter ==> Display information about network adapters.
   -  Enable-NetAdapter -Name "adapter name" ==> Enable a network adapter.
   -  Disable-NetAdapter -Name "adapter name" ==> Disable a network adapter.
   -  Get-NetRoute ==> Display the routing table.
   -  New-NetRoute -DestinationPrefix "prefix" -InterfaceAlias "adapter" -NextHop "gateway" ==> Add a new route to the routing table.
   -  Get-NetFirewallProfile ==> Display firewall profiles and their settings.
   -  Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False ==> Disable the firewall for all profiles.
   -  Get-DnsClientCache ==> Display the DNS client cache.
   -  Clear-DnsClientCache ==> Clear the DNS client cache.
   -  Get-NetConnectionProfile ==> Display the network connection profile.
   -  Get-NetTCPConnection ==> Display active TCP connections.
   -  Get-WinEvent -LogName Security ==> Retrieve entries from the security event log.`)
	}
}

func displayFileSystemDiskCommands(env string) {
	fmt.Println("\nFile System and Disk Management Commands:")
	switch env {
	case "Windows CMD":
		fmt.Println(`**File and Directory Management**
   -  cd /d path ==> Change the current directory.
   -  mkdir directoryname ==> Create a new directory.
   -  rmdir /s /q directoryname ==> Remove a directory and its contents.
   -  del /f /q filename ==> Delete a file.
   -  copy source destination ==> Copy files from one location to another.
   -  xcopy source destination /s /e ==> Copy directories and subdirectories.
   -  robocopy source destination /mir ==> Robust copy for directories.
   -  move source destination ==> Move files from one location to another.
   -  ren oldfilename newfilename ==> Rename a file.
   -  attrib +r -s -h filename ==> Change file attributes (e.g., read-only, system, hidden).
   -  tree /f ==> Display a directory tree structure.
   -  assoc ==> Display or modify file extension associations.
   -  fc file1 file2 ==> Compare two files and display the differences.\n**Disk and File System Commands**
   -  diskpart ==> Manage disk partitions.
   -  format drive==> ==> Format a disk.
   -  label drive==> labelname ==> Create or change a disk label.
   -  chkdsk drive==> /f /r ==> Check a disk for errors and fix them.
   -  convert drive==> /fs==>ntfs ==> Convert a FAT32 volume to NTFS.
   -  diskperf ==> Enable or disable disk performance counters.
   -  vol drive==> ==> Display the volume label and serial number.
   -  fsutil dirty query drive==> ==> Query if a drive is dirty.
   -  compact /c /s==>path ==> Compress files in a directory.
   -  cipher /e /s==>path ==> Encrypt files and directories.
   -  defrag drive==> ==> Defragment a disk.
   -  subst x==> folder ==> Map a folder to a drive letter.\n**Text Processing and Scripting**
   -  echo text ==> Display a line of text.
   -  type filename ==> Display the contents of a file.
   -  find "text" filename ==> Search for text in a file.
   -  findstr "text" filename ==> Search for strings in files.
   -  more filename ==> Display output one screen at a time.
   -  for %variable in (set) do command ==> Loop through a set of values.
   -  if exist filename command ==> Execute a command if a file exists.
   -  call script.bat ==> Call another batch script.
   -  exit ==> Exit the command prompt or a script.
   -  pause ==> Pause the execution of a script and display a message.
   -  rem ==> Add a comment to a batch file.
   -  set /p variable=prompt text ==> Prompt for user input.`)
	case "Linux Shell":
		fmt.Println(`**File and Directory Management**
   -  ls -l ==> List files in long format.
   -  cd /path/to/directory ==> Change directory.
   -  pwd ==> Print the current working directory.
   -  mkdir dirname ==> Create a new directory.
   -  rmdir dirname ==> Remove a directory.
   -  rm -rf dirname ==> Remove a directory and its contents recursively.
   -  cp file1 file2 ==> Copy file1 to file2.
   -  mv file1 file2 ==> Move or rename file1 to file2.
   -  ln -s /path/to/file /path/to/symlink ==> Create a symbolic link.
   -  find /path -name filename ==> Find files by name.
   -  grep 'pattern' file ==> Search for a pattern in a file.
   -  tar -czvf archive.tar.gz /path/to/directory ==> Create a compressed archive.
   -  tar -xzvf archive.tar.gz ==> Extract a compressed archive.
   -  zip -r archive.zip /path/to/directory ==> Create a zip archive.
   -  unzip archive.zip ==> Extract a zip archive.\n**Disk and Filesystem Commands**
   -  fdisk /dev/sdX ==> Partition a hard drive.
   -  mkfs.ext4 /dev/sdX1 ==> Create a filesystem on a partition.
   -  mount /dev/sdX1 /mnt ==> Mount a filesystem.
   -  umount /mnt ==> Unmount a filesystem.
   -  fsck /dev/sdX1 ==> Check and repair a filesystem.
   -  parted /dev/sdX ==> Partition editor.
   -  lsblk ==> List block devices.
   -  blkid ==> Display block device attributes.
   -  du -sh * ==> Display disk usage for all files and directories in the current directory.
   -  df -h ==> Display free disk space on filesystems.
   -  mount -a ==> Mount all filesystems mentioned in fstab.
\n**Text Processing Commands**
   -  cat file ==> Concatenate and display file content.
   -  tac file ==> Display file content in reverse order.
   -  less file ==> View file content one page at a time.
   -  head file ==> Display the first 10 lines of a file.
   -  tail file ==> Display the last 10 lines of a file.
   -  tail -file ==> Continuously monitor a file.
   -  grep 'pattern' file ==> Search for a pattern in a file.
   -  sed 's/old/new/g' file ==> Replace old with new in a file.
   -  awk '{print $1}' file ==> Print the first column of a file.
   -  cut -d'==>' -f1 /etc/passwd ==> Cut the first field from the passwd file.
   -  sort file ==> Sort lines in a file.
   -  uniq file ==> Report or omit repeated lines.
   -  wc -l file ==> Count lines in a file.
   -  tee file ==> Read from standard input and write to standard output and files.
   -  diff file1 file2 ==> Compare two files line by line.
   -  comm file1 file2 ==> Compare two sorted files line by line.\n**Compression and Archiving**
   -  tar -czvf archive.tar.gz /path/to/directory ==> Create a compressed archive.
   -  tar -xzvf archive.tar.gz ==> Extract a compressed archive.
   -  gzip file ==> Compress a file using gzip.
   -  gunzip file.gz ==> Decompress a gzip file.
   -  zip -r archive.zip /path/to/directory ==> Create a zip archive.
   -  unzip archive.zip ==> Extract a zip archive.
   -  bzip2 file ==> Compress a file using bzip2.
   -  bunzip2 file.bz2 ==> Decompress a bzip2 file.
   -  xz file ==> Compress a file using xz.
   -  unxz file.xz ==> Decompress an xz file.`)
	case "PowerShell":
		fmt.Println(`**File System and Disk Management**
   -  Get-ChildItem -Path "path" -Recurse ==> List all files and directories within a path (recursive).
   -  Get-Item -Path "path" ==> Retrieve information about a specific file or directory.
   -  Set-ItemProperty -Path "path" -Name "attribute" -Value "value" ==> Modify file or directory attributes.
   -  Get-ACL -Path "path" ==> Retrieve the access control list (ACL) for a file or directory.
   -  Set-ACL -Path "path" -AclObject $acl ==> Set the ACL for a file or directory.
   -  Get-Disk ==> Retrieve information about disk drives.
   -  Initialize-Disk -Number number ==> Initialize a disk.
   -  New-Partition -DiskNumber number -UseMaximumSize -AssignDriveLetter ==> Create a new partition.
   -  Format-Volume -DriveLetter letter -FileSystem "filesystem" ==> Format a partition with a specific file system.
   -  Get-Volume ==> Display information about volumes.
   -  Set-Volume -DriveLetter letter -NewFileSystemLabel "label" ==> Change the volume label of a drive.
`)
	}
}

func displaySecurityCommands(env string) {
	fmt.Println("\nSecurity and Access Control Commands:")
	switch env {
	case "Windows CMD":
		fmt.Println(`**Security and Access Control**
   -  cacls filename ==> Display or modify access control lists (ACLs) of files.
   -  icacls filename ==> Display, modify, backup, or restore ACLs.
   -  secedit /analyze ==> Analyze system security by comparing the current security configuration to a template.
   -  gpupdate /force ==> Force update of Group Policy settings.
   -  gpresult /r ==> Display the Resultant Set of Policy (RSOP) information.
   -  cipher /w==>C==>\ ==> Wipe deleted files on a drive.
   -  net accounts ==> Display or modify password and logon requirements.
   -  net user username * ==> Change a user's password.
   -  runas /user==>username program ==> Run a program as another user.
`)
	case "Linux Shell":
		fmt.Println(`**Security and Access Control**
   -  chmod 755 file ==> Change file permissions.
   -  chown user==>group file ==> Change file ownership.
   -  passwd username ==> Change a user's password.
   -  gpasswd -a user group ==> Add a user to a group.
   -  sudo command ==> Run a command as another user (typically root).
   -  visudo ==> Edit the sudoers file.
   -  iptables -L ==> List firewall rules.
   -  ufw status ==> Check the status of the Uncomplicated Firewall.
   -  ufw enable ==> Enable the Uncomplicated Firewall.
   -  setfacl -m u==>user==>rwx file ==> Set file ACL for a user.
   -  getfacl file ==> Get file ACL.`)
	case "PowerShell":
		fmt.Println(`**Security and Access Control**
   -  Get-ExecutionPolicy ==> Display the current execution policy.
   -  Set-ExecutionPolicy RemoteSigned ==> Set the execution policy to allow running scripts that are signed.
   -  Get-WindowsFeature ==> List installed and available Windows features.
   -  Install-WindowsFeature -Name featurename ==> Install a Windows feature.
   -  Uninstall-WindowsFeature -Name featurename ==> Uninstall a Windows feature.
   -  Get-AuthenticodeSignature -FilePath "path" ==> Check the digital signature of a file.
   -  Set-AuthenticodeSignature -FilePath "path" -Certificate "certificate" ==> Sign a script or file with a certificate.
   -  Get-LocalUser | Where-Object {$_.PasswordExpired -eq $true} ==> List users whose passwords have expired.
   -  Get-WinEvent -LogName Security -MaxEvents 10 ==> Retrieve the latest 10 security event log entries.
   -  New-Item -Path "HKCU==>\Software\MyApp" -Force ==> Create a new registry key.
   -  Remove-Item -Path "HKCU==>\Software\MyApp" ==> Delete a registry key.
   -  Get-FileHash -Path "path" ==> Compute the hash of a file.`)
	}
}

func displayBackupRestoreCommands(env string) {
	fmt.Println("\nBackup and Restore Commands:")
	switch env {
	case "Windows CMD":
		fmt.Println(` **Backup and Restore**
   -  wbadmin start backup ==> Start a one-time backup.
   -  wbadmin get versions ==> List details of backups.
   -  wbadmin start recovery ==> Start a recovery operation.
   -  robocopy /mir source destination ==> Mirror a directory.
   -  xcopy /s /e source destination ==> Copy directories and subdirectories.
   -  diskshadow ==> Manage shadow copies (Volume Shadow Copy Service).
   -  recoverydrive ==> Create a recovery drive.
`)
	case "Linux Shell":
		fmt.Println(`**Backup and Restore**
   -  rsync -av /source /destination ==> Synchronize files between locations.
   -  dd if=/dev/sdX of=/path/to/backup.img ==> Create a disk image.
   -  dd if=/path/to/backup.img of=/dev/sdX ==> Restore a disk image.
   -  tar -czvf /path/to/backup.tar.gz /path/to/directory ==> Create a compressed backup.
   -  tar -xzvf /path/to/backup.tar.gz -C /path/to/restore ==> Restore from a compressed backup.
   -  dump -0u -f /path/to/backup.dump /dev/sdX1 ==> Backup an ext2/ext3 filesystem.
   -  restore -if /path/to/backup.dump ==> Restore an ext2/ext3 filesystem.
`)
	case "PowerShell":
		fmt.Println(`**Backup and Restore**
   -  Start-Backup -Policy "policyname" ==> Start a backup using a specific policy.
   -  Get-BackupCatalog ==> Retrieve information about backup catalogs.
   -  Start-Restore -Backup "backupname" ==> Start a restore operation from

`)
	}
}

func displayRemoteCommands(env string) {
	fmt.Println("\nRemote Commands:")
	switch env {
	case "Windows CMD":
		fmt.Println(`**Remote Commands**
   -  mstsc ==> Start Remote Desktop Connection.
   -  psexec \\computer cmd ==> Execute commands remotely.
   -  shutdown /m \\computer /r ==> Remotely restart a computer.
   -  net use \\computer\share ==> Map a network share.
   -  net session \\computer ==> Display or end a session with a remote computer.
   -  wmic /node==>"computer" process call create "cmd.exe" ==> Execute a command on a remote computer using WMI.`)
	case "Linux Shell":
		fmt.Println("  - ssh user@remote: Connect to a remote system via SSH.")
		fmt.Println("  - scp file user@remote:/path: Copy files to a remote system.")
		fmt.Println("  - rsync -avz user@remote:/path localpath: Sync files with a remote system.")
	case "PowerShell":
		fmt.Println("  - Enter-PSSession -ComputerName remoteComputer: Start a remote PowerShell session.")
		fmt.Println("  - Invoke-Command -ComputerName remoteComputer -ScriptBlock { commands }: Run commands on a remote computer.")
	}
}
