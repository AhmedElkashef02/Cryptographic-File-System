# Cryptographic-File-System
implementing a simple cryptographic file system in the FreeBSD kernel at the VFS layer. This file system will encrypt on a per-file basis, in contrast to what is commonly known as full-disk encryption.

## Automated Setup
- Run the executable file, which will remove and replace a set of files, mount the new cryptographic filesystem, install the system call, and add th read/write functions in the VFS layer. Use:`./setup`
- build & install new kernel
- Reboot

## Important structs that we modified

Stat struct: found in stat.h
```
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct stat {
    dev_t     st_dev;     /* ID of device containing file */
    ino_t     st_ino;     /* inode number */
    mode_t    st_mode;    /* protection */
    nlink_t   st_nlink;   /* number of hard links */
    uid_t     st_uid;     /* user ID of owner */
    gid_t     st_gid;     /* group ID of owner */
    dev_t     st_rdev;    /* device ID (if special file) */
    off_t     st_size;    /* total size, in bytes */
    blksize_t st_blksize; /* blocksize for file system I/O */
    blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
    time_t    st_atime;   /* time of last access */
    time_t    st_mtime;   /* time of last modification */
    time_t    st_ctime;   /* time of last status change */
};
```

iovec struct: input/output vector, used to initialize the buffer for encryption/decryption
```
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

struct iovec {
		   char	  *iov_base;  /* Base address. */
		   size_t iov_len;    /* Length. */
};
```

vattr struct: vnode attributes, used to get current user's ID, and file access mode and type, found in vnode.h
```
struct vattr {
	enum vtype	va_type;	/* vnode type (for create) */
	u_short		va_mode;	/* files access mode and type */
	u_short		va_padding0;
	uid_t		va_uid;		/* owner user id */
	gid_t		va_gid;		/* owner group id */
	nlink_t		va_nlink;	/* number of references to file */
	dev_t		va_fsid;	/* filesystem id */
	ino_t		va_fileid;	/* file id */
	u_quad_t	va_size;	/* file size in bytes */
	long		va_blocksize;	/* blocksize preferred for i/o */
	struct timespec	va_atime;	/* time of last access */
	struct timespec	va_mtime;	/* time of last modification */
	struct timespec	va_ctime;	/* time file changed */
	struct timespec	va_birthtime;	/* time file created */
	u_long		va_gen;		/* generation number of file */
	u_long		va_flags;	/* flags defined for file */
	dev_t		va_rdev;	/* device the special file represents */
	u_quad_t	va_bytes;	/* bytes of disk space held by file */
	u_quad_t	va_filerev;	/* file modification number */
	u_int		va_vaflags;	/* operations flags, see below */
	long		va_spare;	/* remain quad aligned */
};
```

uio struct: device driver I/O	routines
```
#include <sys/types.h>
#include <sys/uio.h>

struct uio {
	     struct  iovec *uio_iov;	     /*	scatter/gather list */
	     int     uio_iovcnt;	     /*	length of scatter/gather list */
	     off_t   uio_offset;	     /*	offset in target object	*/
	     ssize_t uio_resid;		     /*	remaining bytes	to copy	*/
	     enum    uio_seg uio_segflg;     /*	address	space */
	     enum    uio_rw uio_rw;	     /*	operation */
	     struct  thread *uio_td;	     /*	owner */
 };
```
The functions uiomove() and uiomove_nofault() are used to transfer	data between buffers and I/O vectors that might	possibly cross the user/kernel space boundary.

ucred struct: user credentials and information
```
struct ucred {
	u_int	cr_ref;			/* reference count */
#define	cr_startcopy cr_uid
	uid_t	cr_uid;			/* effective user id */
	uid_t	cr_ruid;		/* real user id */
	uid_t	cr_svuid;		/* saved user id */
	int	cr_ngroups;		/* number of groups */
	gid_t	cr_rgid;		/* real group id */
	gid_t	cr_svgid;		/* saved group id */
	struct uidinfo	*cr_uidinfo;	/* per euid resource consumption */
	struct uidinfo	*cr_ruidinfo;	/* per ruid resource consumption */
	struct prison	*cr_prison;	/* jail(2) */
	struct loginclass	*cr_loginclass; /* login class */
	u_int		cr_flags;	/* credential flags */
	void 		*cr_pspare2[2];	/* general use 2 */
#define	cr_endcopy	cr_label
	struct label	*cr_label;	/* MAC label */
	struct auditinfo_addr	cr_audit;	/* Audit properties. */
	gid_t	*cr_groups;		/* groups */
	int	cr_agroups;		/* Available groups */
	gid_t   cr_smallgroups[XU_NGROUPS];	/* storage for small groups */
	unsigned int k0;			/* first part of the key */
	unsigned int k1;			/* second part of the key */
};
```
