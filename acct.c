#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/smr.h>
#include <sys/fcntl.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <lib/libkern/libkern.h>
#include <sys/tty.h>
#include <sys/resourcevar.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/poll.h>
#include <sys/rwlock.h>
#include <sys/select.h>

#include "acct.h"

void 	acctattach(struct process *);
int 	acctopen(dev_t, int, int, struct proc *);
int 	acctclose(dev_t, int, int, struct proc *);
int 	acctread(dev_t dev, struct uio *uio, int flags);
int 	acctioctl(dev_t, u_long, caddr_t, int, struct proc *);
int 	acctpoll(dev_t, int, struct proc *);
void 	assign_common_fields(struct acct_common *, struct process *);
int	    filt_acctread(struct knote *, long);
void	filt_acctdetach(struct knote *);

struct message {
	SIMPLEQ_ENTRY(message) 	entry;
	int type;
	size_t len;
	union {
		struct acct_fork *fork;
		struct acct_exec *exec;
		struct acct_exit *exit;
	} m_type;
};

SIMPLEQ_HEAD(message_list, message);
struct message *e;
struct message_list messages = SIMPLEQ_HEAD_INITIALIZER(messages);
int incrementer; /* How many messages have there been. Used to set ac_seq field*/
int open = 0; /* Keeping track of whether or not the file is open */
int blocking = 1;
const char *name = "queueLock";
struct rwlock rwl;
struct selinfo acct_rsel;

struct filterops acctread_filtops = {1, NULL, filt_acctdetach, filt_acctread};

/**
 * Process information about a recently-forked process, 
 * and stores this information in a message.
 */
void
acct_fork(struct process *forkedProc)
{
#ifdef DEBUG
	log(LOG_DEBUG, "acct_fork\n");
#endif
	if (!open)
		return;
	struct acct_common commonPart;
	struct message *new = malloc(sizeof(struct message), M_DEVBUF,
			M_NOWAIT | M_ZERO | M_CANFAIL);
	if (new == NULL) {
	       	log(LOG_CRIT, "malloc failed\n");
		return;
	}
	commonPart.ac_type = ACCT_MSG_FORK;
	assign_common_fields(&commonPart, forkedProc->ps_pptr);
#ifdef DFIELDS
	log(LOG_DEBUG, "commonPart.ac_comm: %s\n", commonPart.ac_comm);
	log(LOG_DEBUG, "ac_type: %d, ac_seq: %d\n", commonPart.ac_type,
	    commonPart.ac_seq);
	log(LOG_DEBUG, "ac_btime seconds: %lld\n", commonPart.ac_btime.tv_sec);
	log(LOG_DEBUG, "pid: %d, uid: %d, gid: %d, tty: %d\n", 
	    commonPart.ac_pid, commonPart.ac_uid, commonPart.ac_gid, 
	    commonPart.ac_tty);
#endif
	new->type = ACCT_MSG_FORK;
	new->m_type.fork = malloc(sizeof(struct acct_fork), M_DEVBUF,
			M_NOWAIT | M_ZERO | M_CANFAIL);
	if (new->m_type.fork == NULL) {
	       	log(LOG_CRIT, "malloc failed\n");
		return;
	}
	memcpy(&new->m_type.fork->ac_common, &commonPart, sizeof(commonPart));
	new->m_type.fork->ac_cpid = forkedProc->ps_pid;
	new->m_type.fork->ac_common.ac_len = sizeof(struct acct_fork);
	new->len = sizeof(struct acct_fork);

	rw_enter_write(&rwl);
	SIMPLEQ_INSERT_TAIL(&messages, new, entry);
	wakeup(&messages);
	selwakeup(&acct_rsel);
	rw_exit_write(&rwl);
}

/**
 * Stores information about a recently-executed process into the message queue.
 */
void
acct_exec(struct process *execdProc)
{
	struct acct_common commonPart;
	struct message *new;
#ifdef DEBUG
	log(LOG_DEBUG, "acct_exec\n");
#endif
	if (!open)
		return;
	new = malloc(sizeof(struct message), M_DEVBUF,
	    M_NOWAIT | M_ZERO | M_CANFAIL);
	if (new == NULL) {
	       	log(LOG_CRIT, "malloc failed\n");
		return;
	}
	commonPart.ac_type = ACCT_MSG_EXEC;
	assign_common_fields(&commonPart, execdProc->ps_pptr);

#ifdef DFIELDS
	log(LOG_DEBUG, "commonPart.ac_comm: %s\n", commonPart.ac_comm);
	log(LOG_DEBUG, "ac_type: %d, ac_seq: %d\n", commonPart.ac_type,
	    commonPart.ac_seq);
	log(LOG_DEBUG, "ac_btime seconds: %lld\n", commonPart.ac_btime.tv_sec);
	log(LOG_DEBUG, "pid: %d, uid: %d, gid: %d, tty: %d\n", 
	    commonPart.ac_pid, commonPart.ac_uid, commonPart.ac_gid, 
	    commonPart.ac_tty);
#endif
	new->type = ACCT_MSG_EXEC;
	new->m_type.exec = malloc(sizeof(struct acct_exec), M_DEVBUF,
			M_NOWAIT | M_ZERO | M_CANFAIL);
	if (new->m_type.exec == NULL) {
	       	log(LOG_CRIT, "malloc failed\n");
		return;
	}
	memcpy(&new->m_type.exec->ac_common, &commonPart, sizeof(commonPart));
	/* Update size of message */
	new->m_type.exec->ac_common.ac_len = sizeof(struct acct_exec);
	new->len = sizeof(struct acct_exec);

	rw_enter_write(&rwl);
	SIMPLEQ_INSERT_TAIL(&messages, new, entry);
	wakeup(&messages);
	selwakeup(&acct_rsel);
	rw_exit_write(&rwl);
}

/**
 * Stores information about a recently-exited process into the message queue.
 */
void
acct_exit(struct process *exitedProc)
{
#ifdef DEBUG
	log(LOG_DEBUG, "acct_exit\n");
#endif
	if (!open)
		return;
	struct rusage *r;
	struct timespec ut, st;
	struct acct_common commonPart;
	struct message *new = malloc(sizeof(struct message), M_DEVBUF,
			M_NOWAIT | M_ZERO | M_CANFAIL);

	if (new == NULL) {
	       	log(LOG_CRIT, "malloc failed\n");
		return;
	}
	commonPart.ac_type = ACCT_MSG_EXIT;
	assign_common_fields(&commonPart, exitedProc->ps_pptr);
	
#ifdef DFIELDS
	log(LOG_DEBUG, "commonPart.ac_comm: %s\n", commonPart.ac_comm);
	log(LOG_DEBUG, "ac_type: %d, ac_seq: %d\n", commonPart.ac_type,
	    commonPart.ac_seq);
	log(LOG_DEBUG, "ac_btime seconds: %lld\n", commonPart.ac_btime.tv_sec);
	log(LOG_DEBUG, "pid: %d, uid: %d, gid: %d, tty: %d\n", 
	    commonPart.ac_pid, commonPart.ac_uid, commonPart.ac_gid, 
	    commonPart.ac_tty);
#endif
	new->type = ACCT_MSG_EXIT;
	new->m_type.exit = malloc(sizeof(struct acct_fork), M_DEVBUF,
			M_NOWAIT | M_ZERO | M_CANFAIL);
	if (new->m_type.exit == NULL) {
	       	log(LOG_CRIT, "malloc failed\n");
		return;
	}
	memcpy(&new->m_type.exit->ac_common, &commonPart, sizeof(commonPart));

	/* The amount of user and system time used. 
	 * Interrupt time isn't required. */
	calctsru(&exitedProc->ps_tu, &ut, &st, NULL);
	new->m_type.exit->ac_utime = ut;
	new->m_type.exit->ac_stime = st;

	/* Update size of message */
	new->m_type.exit->ac_common.ac_len = sizeof(struct acct_exit);
	new->len = sizeof(struct acct_exit);

	/* Memory used and count of IO blocks */
	r = &exitedProc->ps_mainproc->p_ru;
	new->m_type.exit->ac_mem = r->ru_ixrss + r->ru_idrss + r->ru_isrss;
#ifdef DEBUG
	log(LOG_DEBUG, "ac_mem: %llu\n", new->m_type.exit->ac_mem);
#endif
	new->m_type.exit->ac_io = r->ru_inblock + r->ru_oublock;

	rw_enter_write(&rwl);
	SIMPLEQ_INSERT_TAIL(&messages, new, entry);
	wakeup(&messages);
	selwakeup(&acct_rsel);
	rw_exit_write(&rwl);
}

/**
 * Each message has certain field that are common.
 * Process field from the struct process and store them in common part of message.
 */
void	
assign_common_fields(struct acct_common *commonPart,
    struct process *proc)
{
	struct timespec tmp;
	/* assert ac_comm is less than ps_comm */
	CTASSERT(sizeof(commonPart->ac_comm) <= sizeof(proc->ps_comm));
	memcpy(commonPart->ac_comm, proc->ps_comm, 
	    sizeof(commonPart->ac_comm));
	commonPart->ac_seq = incrementer;
	incrementer++;
	memcpy(&commonPart->ac_btime, &proc->ps_start,  
	    sizeof(proc->ps_start));
	getnanotime(&tmp);
	timespecsub(&tmp, &proc->ps_start, &tmp);
	commonPart->ac_etime = tmp;

	/* PID, UID and GID */
	commonPart->ac_pid = proc->ps_pid;
	commonPart->ac_uid = proc->ps_ucred->cr_ruid;
	commonPart->ac_gid = proc->ps_ucred->cr_rgid;
	if ((proc->ps_flags & PS_CONTROLT) &&
	    proc->ps_pgrp->pg_session->s_ttyp)
		commonPart->ac_tty = proc->ps_pgrp->pg_session->s_ttyp->t_dev;
	commonPart->ac_flag = proc->ps_acflag;
}

/**
 * Called when the kernel starts.
 * Initialises incrementer and the read-write lock
 */
void
acctattach(struct process *proc)
{
	incrementer = 0;
	rw_init(&rwl, name);
}

/**
 * Called when a user opens this file.
 * Sets relevant flags/variables, does error checking.
 */
int
acctopen(dev_t dev, int flag, int mode, struct proc *p)
{
	open = 1;
	if (flag & O_NONBLOCK) {
#ifdef DEBUG
		log(LOG_DEBUG, "NONBLOCK\n");
#endif
		blocking = 0;
	}
	if (minor(dev) != 0)
		return (ENXIO);

	if (flag & FWRITE)
		return (EPERM);
	incrementer = 0;
	return 0;
}

/**
 * Called when a user closes this file.
 * Mostly for emptying message queue.
 */
int
acctclose(dev_t dev, int flag, int mode, struct proc *closedProc)
{
	struct message *n1;
	open = 0;
	rw_enter_write(&rwl);
	while (!SIMPLEQ_EMPTY(&messages)) {
		n1 = SIMPLEQ_FIRST(&messages);
		SIMPLEQ_REMOVE_HEAD(&messages, entry);
		switch (n1->type) {
		case ACCT_MSG_FORK:
			free(n1->m_type.fork, M_DEVBUF, 
			    sizeof(struct acct_fork)) ;
			break;
		case ACCT_MSG_EXEC:
			free(n1->m_type.exec, M_DEVBUF, 
			    sizeof(struct acct_exec)) ;
			break;
		case ACCT_MSG_EXIT:
			free(n1->m_type.exit, M_DEVBUF, 
			    sizeof(struct acct_exit)) ;
			break;
		}
		free(n1, M_DEVBUF, sizeof(struct message));
	}
	rw_exit_write(&rwl);
	return 0;
}

/**
 * Supports FIONREAD and FIONBIO as per the ioctl(2) manpage.
 */
int
acctioctl(dev_t dev, u_long cmd, caddr_t data, int flags, struct proc *p)
{
	struct message *n1;
	if (cmd == FIONREAD) {
#ifdef DEBUG
		log(LOG_DEBUG, "fionread\n");
#endif
		if (SIMPLEQ_EMPTY(&messages))
			return 0;
		n1 = SIMPLEQ_FIRST(&messages);
		*data = n1->len;
		return 0;
	} else if (cmd == FIONBIO) {
#ifdef DEBUG
		log(LOG_DEBUG, "fionbio\n");
#endif
		if (*data) {
			blocking = 0;
		}
		else
			blocking = 1;
	} else {
#ifdef DEBUG
		log(LOG_DEBUG, "einval\n");
#endif
		return EINVAL;
	}
	return 0;
}

/**
 * Dequeues a single message, then copies as much of it as possible to userland
 */
int
acctread(dev_t dev, struct uio *uio, int flags)
{
	int error;
	size_t len;
	struct message *nextMessage;
	
	if (uio->uio_offset < 0) {
#ifdef DEBUG
		log(LOG_DEBUG, "uio_offset bad\n");
#endif
		return (EINVAL);
	}

	if (SIMPLEQ_EMPTY(&messages)) {
#ifdef DEBUG
		log(LOG_DEBUG, "acctread called on empty queue\n");
#endif
		if (!blocking)
			return (EAGAIN);
		error = tsleep(&messages, PRIBIO | PCATCH, "noMessages", 0);
		if (error)
			return error;
	}
	nextMessage = SIMPLEQ_FIRST(&messages);
	rw_enter_write(&rwl);
	SIMPLEQ_REMOVE_HEAD(&messages, entry);
	rw_exit_write(&rwl);
	len = nextMessage->len;

	if (uio->uio_offset >= len) {
		//return 0;
	}
	if (len > uio->uio_resid) {
		//len = uio->uio_resid; TODO
#ifdef DEBUG
		log(LOG_DEBUG, "len shorted to: %zu\n", len);
#endif
	}
	switch (nextMessage->type) {
	case ACCT_MSG_FORK:
		if ((error = uiomove((void*)nextMessage->m_type.fork, 
		    len, uio)) != 0)
			return (error);
		free(nextMessage->m_type.fork, M_DEVBUF, 
	    	    sizeof(struct acct_fork)) ;
		break;
	case ACCT_MSG_EXEC:
		if ((error = uiomove((void*)nextMessage->m_type.exec, 
		    len, uio)) != 0)
			return (error);
		free(nextMessage->m_type.exec, M_DEVBUF, 
	    	    sizeof(struct acct_exec)) ;
		break;
	case ACCT_MSG_EXIT:
		if ((error = uiomove((void*)nextMessage->m_type.exit, 
		    len, uio)) != 0)
			return (error);
		free(nextMessage->m_type.exit, M_DEVBUF, 
	    	    sizeof(struct acct_exit)) ;
		break;
	}
	free(nextMessage, M_DEVBUF, sizeof(struct message));
	return 0;
}

/**
 * Driver does not support being written to by userland.
 * Returns EOPNOTSUPP
 */
int
acctwrite(dev_t dev, struct uio *uio, int flags)
{
	return EOPNOTSUPP;
}

/**
 * Support for non-blocking.
 */
int
acctpoll(dev_t dev, int events, struct proc *p)
{
	int revents;

	revents = 0;
	
    // Check if user wants non-blocking.
	if (events & (POLLIN | POLLRDNORM)) {
		if (SIMPLEQ_EMPTY(&messages)) {
#ifdef DEBUG
			log(LOG_DEBUG, "poll() empty queue\n");
#endif
            // Object not ready for I/O. Record that this thread is interested in IO
			selrecord(p, &acct_rsel);
		} else {
            // There is data to be read.
			revents |= events & (POLLIN | POLLRDNORM);
        }
	}
	return (revents);
}

/**
 * Adds new knote to the kernel note list.
 * This effectively "hooks on" the process for notifications.
 */
int
acctkqfilter(dev_t dev, struct knote *kn)
{
	struct klist *klist;
	switch (kn->kn_filter) {
	case EVFILT_READ:
		klist = &acct_rsel.si_note; /* kernel note list */
		kn->kn_fop = &acctread_filtops; /* filters for detach and read */
		break;
	default:
		return (EINVAL);
	}
    /* Add this knote to the list to be filtered with acctread_filtops as its filter methods */
	SLIST_INSERT_HEAD(klist, kn, kn_selnext); 
	return 0;
}

/**
 * Removes a knote struct from kernel event notifications mechanism.
 */
void
filt_acctdetach(struct knote *kn)
{
    /* As long as it's not already detached, remove it from kernel note list */
	if (!(kn->kn_status & KN_DETACHED))
		SLIST_REMOVE(&acct_rsel.si_note, kn, knote, kn_selnext);
}

/**
 * If note is appropriately hooked into the kqueue kernel event notification mechanism,
 * provide the first message in the kn_data field of the knote.
 */
int
filt_acctread(struct knote *kn, long hint)
{
	struct message *nextMessage;
	if (kn->kn_status & KN_DETACHED) {
		kn->kn_data = 0;
		return 1;
	}
	if (SIMPLEQ_EMPTY(&messages))
		return 0;
	nextMessage = SIMPLEQ_FIRST(&messages);
	kn->kn_data = nextMessage->len;
	return 1;
}
