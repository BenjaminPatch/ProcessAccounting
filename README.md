# ProcessAccounting
Process Accounting Pseudo Device Drive.
## Compilation
The program is to be built as part of the kernel on an amd64 OpenBSD 6.5.
The changes to the kernel necessary to configure an acct(4) driver so it can be compiled is supplied as `initial-boilerplate.diff`. The diff can be applied by running the following:
```
~$ cd /usr/src/sys
sys$ patch < /path/to/assignment2-boilerplate.diff
Hmm...  Looks like a unified diff to me...
```
The driver code exists in `acct.c`, and should be placed in `sys/dev/acct.c` next to the `sys/dev/acct.h` provided by the diff described above.

## Messages
The messages that a program reads from the device driver are represented as a set of structs. The kernel driver populates the structs when it is open and the relevant events occur in the kernel, and then makes them available for a program to read. The structure of the messages the driver produces are provided in `sys/dev/acct.h`.

#### Common Fields
All messages from the driver start with a common set of fields that are contained in struct acct_common. The other messages all contain struct acct_common as their first field.
The first three fields of the common structure refer to the message itself, rather than the process the message is about. The ac_type field contains a number representing the type of the current message, eg, avalue of 0 or ACCT_MSG_FORK states that the message is about a process forking and is interpreted as the associated message structure.

The ac_len field contains the number of bytes used for this message, including the ac_type and ac_len fields.

ac_seq is a simple wrapping counter that increments for every message that the driver generates. If the driver receives notification from the rest of the kernel that an event has occurred (eg, acct_fork() is called when a process forks), but is unable to generate a message about it, the sequence number is still incremented so that the userland consumer of the messages will know that an event has been lost. The counter is reset to 0 when the acct(4) device is opened.

The remaining common fields are set for the process the message is about.

#### exit message
The exit message corresponds with struct acct_exit. The information in this message corresponds with the information described in acct(5). acct(2) is used as a reference when filling in the information in this message.

#### fork event
The fork message corresponds with struct acct_fork, and is generated when a process forks a new child. The information in the message is based on the parent of the new process, apart from ac_cpid which contains the process ID of the new child. Note that acct_fork is given a pointer to the child, not the parent.

#### exec event
The exec message corresponds with struct acct_exec, and is generated when a process calls exec(). It exists to record the new name of the binary the program is executing.


## Driver entry points
acct.c provides the following functions to support the integration into the kernel, and to provide the required interface for userland to access the driver.

#### Kernel entry points
The kernel is patched to call 3 functions when a process forks, execs, or exits. Those functions are acct_fork(), acct_exec(),  and acct_exit() respectively. All these functions take a struct process* as their only argument, and do not return anything to the caller.

#### Userland entry points
acctattach() is called when the kernel starts running for the driver to configure any state needed for it to operate.

acctopen() is called when a program attempts to open a device file with the corresponding major number to this driver. It allows only the 0th minor to be opened, opened exclusively, and only opened for reading. Read/write or write-only opens of the device fail with EPERM. The sequence number for generated messages is reset to 0 on every open.

acctclose() cleans up any state associated with the open driver.

acctioctl() supports FIONREAD, and FIONBIO as per theioctl(2) manpage.

acctread() dequeues a single message, and copies as much of that one message as possible to userland. It supports non-blocking reads.

acctwrite() returns EOPNOTSUPP as the driver does not support being written to by a userland process.

The driver supports non-blocking I/O (well, just O) by implementing acctpoll() and acctkqfilter().
