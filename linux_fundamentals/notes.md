# Linux Fundamentals Notes



### Linux File System

| `/`      | The top-level directory is the root filesystem and contains all of the files required to boot the operating system before other filesystems are mounted, as well as the files required to boot the other filesystems. After boot, all of the other filesystems are mounted at standard mount points as subdirectories of the root. |
| -------- | ------------------------------------------------------------ |
| `/bin`   | Contains essential command binaries.                         |
| `/boot`  | Consists of the static bootloader, kernel executable, and files required to boot the Linux OS. |
| `/dev`   | Contains device files to facilitate access to every hardware device attached to the system. |
| `/etc`   | Local system configuration files. Configuration files for installed applications may be saved here as well. |
| `/home`  | Each user on the system has a subdirectory here for storage. |
| `/lib`   | Shared library files that are required for system boot.      |
| `/media` | External removable media devices such as USB drives are mounted here. |
| `/mnt`   | Temporary mount point for regular filesystems.               |
| `/opt`   | Optional files such as third-party tools can be saved here.  |
| `/root`  | The home directory for the root user.                        |
| `/sbin`  | This directory contains executables used for system administration (binary system files). |
| `/tmp`   | The operating system and many programs use this directory to store temporary files. This directory is generally cleared upon system boot and may be deleted at other times without any warning. |
| `/usr`   | Contains executables, libraries, man files, etc.             |
| `/var`   | This directory contains variable data files such as log files, email in-boxes, web application related files, cron files, and more. |



### Privileged vs. Unprivileged User

```shell-session
<username>@<hostname>[~]$
```

The dollar sign, in this case, stands for a user. As soon as we log in as `root`, the character changes to a `hash` <`#`> and looks like this:



```shell-session
root@htb[/htb]#
```

For example, when we upload and run a shell on the target system, we may not see the username, hostname, and current working directory. This may be due to the PS1 variable in the environment not being set correctly.



### Tool to understand long shell commands

https://explainshell.com/



### Important commands for basic information about a given system

| **Command** | **Description**                                              |
| ----------- | ------------------------------------------------------------ |
| `whoami`    | Displays current username.                                   |
| `id`        | Returns users identity                                       |
| `hostname`  | Sets or prints the name of current host system.              |
| `uname`     | Prints basic information about the operating system name and system hardware. |
| `pwd`       | Returns working directory name.                              |
| `ifconfig`  | The ifconfig utility is used to assign or to view an address to a network interface and/or configure network interface parameters. |
| `ip`        | Ip is a utility to show or manipulate routing, network devices, interfaces and tunnels. |
| `netstat`   | Shows network status.                                        |
| `ss`        | Another utility to investigate sockets.                      |
| `ps`        | Shows process status.                                        |
| `who`       | Displays who is logged in.                                   |
| `env`       | Prints environment or sets and executes command.             |
| `lsblk`     | Lists block devices.                                         |
| `lsusb`     | Lists USB devices                                            |
| `lsof`      | Lists opened files.                                          |
| `lspci`     | Lists PCI devices.                                           |



### Most important commands

`whoami`: Find out which user you are, to then find out which privileges you have

`id`: Check which permissions users / groups have

`uname -a`: Print all the information, `uname -r` to print only the Kernel Release version and search for exploits online with that info

`ssh [username]@[IP address]`: To ssh into a remote server

`pwd` : print working directory

`ls -l`: First thing visible is "Total: 32", which is the total number of blocks. Calculate like this: 2 blocks * 1024 bytes/block = 32,768 bytes (or 32 KB).

`cd -`: Jump to the previous directory you were in 

`[Ctrl] + [R]`: search all previously used commands in shell

`[Ctrl] + [L]`: same as `clear`

`tree .`: Visualize the directory / file structure

`mkdir -p Storage/local/user/documents`: Create several directories

`touch info.txt`: Create file

`mv info.txt information.txt`: Rename file info.txt to information.txt

`mv information.txt readme.txt Storage/`: Move information.txt & readme.txt to `Storage/`

`ls -la -c -lt /var/backups`: Show files sorted by modification date

`ls -i /var/backups/shadow.bak`: Get inode number of file





### Search / Find

`which python`: Prints path of filename. Use to check if programs like curl, netcat etc are available. 

`find <location> <options>`: Find files & folders, filter for file size, types etc.

`find / -type f -name *.conf -user root -size +20k -newermt 2020-03-03 -exec ls -al {} \; 2>/dev/null`:

| **Option**            | **Description**                                              |
| --------------------- | ------------------------------------------------------------ |
| `-type f`             | Hereby, we define the type of the searched object. In this case, '`f`' stands for '`file`'. |
| `-name *.conf`        | With '`-name`', we indicate the name of the file we are looking for. The asterisk (`*`) stands for 'all' files with the '`.conf`' extension. |
| `-user root`          | This option filters all files whose owner is the root user.  |
| `-size +20k`          | We can then filter all the located files and specify that we only want to see the files that are larger than 20 KiB. |
| `-newermt 2020-03-03` | With this option, we set the date. Only files newer than the specified date will be presented. |
| `-exec ls -al {} \;`  | This option executes the specified command, using the curly brackets as placeholders for each result. The backslash escapes the next character from being interpreted by the shell because otherwise, the semicolon would terminate the command and not reach the redirection. |
| `2>/dev/null`         | This is a `STDERR` redirection to the '`null device`', which we will come back to in the next section. This redirection ensures that no errors are displayed in the terminal. This redirection must `not` be an option of the 'find' command. |

`find / -type f -name *.conf -newermt 2020-03-03 -size +25k -size -28k -exec ls -al {} \; 2>/dev/null`: Find between specific file sizes

#### Using `locate` (faster)

1. `sudo updatedb`: Update the database
2. `locate *.conf`: Use.

`locate -c *.bak`: count number of files ending in .bak



### STDIN, STDOUT, STDERR

1. Data Stream for Input
   - `STDIN – 0`
2. Data Stream for Output
   - `STDOUT – 1`
3. Data Stream for Output that relates to an error occurring.
   - `STDERR – 2`

`find /etc/ -name shadow 2> stderr.txt 1> stdout.txt`: Redirect outputs to different files.

`find /etc/ -name passwd >> stdout.txt 2>/dev/null`: Use `>>` to append to end of file instead of creating a new file.

`cat << EOF > stream.txt`: Write all written input into stream.txt, until I type "EOF".

`find /etc/ -name *.conf 2>/dev/null | grep systemd | wc -l`: Search in `/etc/` for all files that end with `.conf`, use `grep` to only show the results containing `systemd`, and use `wc -l` to count the lines.



### More and Less

`more`: prints the top part of a text file and output remains in terminal

`less`: same as more but doesn't remain in terminal

`head`: First 10 lines

`tail`: Last 10 lines

`sort`: Sorts alphabetically or numerically, example `cat /etc/passwd | sort`.

`cat /etc/passwd | grep "/bin/bash"`: Search a file for `/bin/bash`

`cat /etc/passwd | grep -v "false\|nologin"`: Omit all results containing `false` or `nologin`. The `\` is used to escape the `|` or-operator.

`cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1`: Use `cut -d":" -f1` to separate text at specified delimiters like `:`, and print only the first occurence in every line with `-f1`

`cat /etc/passwd | grep -v "false\|nologin" | tr ":" " "`: Use `tr ":" " "` to replace all characters `:` with empty spaces.

`cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | column -t`: Use `column -t` to display results in tabular form.

`cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}'`: Use `awk '{print $1, $NF}'` to print only first and last result

`sed 's/bin/HTB/g'`: Substitute (`s`) all (`g`) strings `bin` with `HTB`. Example: `cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}' | sed 's/bin/HTB/g'`

`wc -l`: Count the lines / print how many successful matches we have.

netstat -l --protocol=inet | grep -v "localhost" | grep "LISTEN"

`netstat -l --protocol=inet | grep LISTEN | grep -v localhost | wc -l`: Count number of ipv4 services that are listening, and are not on localhost.

`curl https://www.inlanefreight.com | tr "\"" "\n" | tr "\'" "\n" | grep "https://www.inlanefreight.com/*" | sort -u | wc -l`:  Filter all unique paths of the domain `https://inlanefreight.com`. 









