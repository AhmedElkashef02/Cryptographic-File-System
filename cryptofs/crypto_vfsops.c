/*-
 * Copyright (c) 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)crypto_vfsops.c	8.2 (Berkeley) 1/21/94
 *
 * @(#)lofs_vfsops.c	1.2 (Berkeley) 6/18/92
 * $FreeBSD: releng/10.3/sys/fs/crypto.s/crypto_vfsops.c 282270 2015-04-30 12:39:24Z rmacklem $
 */

/*
 * Crypto Layer
 * (See crypto_vnops.c for a description of what this does.)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/jail.h>

#include <fs/crypto.s/crypto.h>

static MALLOC_DEFINE(M_CRYPTOFSMNT, "crypto.s_mount", "CRYPTOFS mount structure");

static vfs_fhtovp_t	crypto.s_fhtovp;
static vfs_mount_t	crypto.s_mount;
static vfs_quotactl_t	crypto.s_quotactl;
static vfs_root_t	crypto.s_root;
static vfs_sync_t	crypto.s_sync;
static vfs_statfs_t	crypto.s_statfs;
static vfs_unmount_t	crypto.s_unmount;
static vfs_vget_t	crypto.s_vget;
static vfs_extattrctl_t	crypto.s_extattrctl;

/*
 * Mount crypto.layer
 */
static int
crypto.s_mount(struct mount *mp)
{
	int error = 0;
	struct vnode *lowerrootvp, *vp;
	struct vnode *crypto._rootvp;
	struct crypto_mount *xmp;
	struct thread *td = curthread;
	char *target;
	int isvnunlocked = 0, len;
	struct nameidata nd, *ndp = &nd;

	CRYPTOFSDEBUG("crypto.s_mount(mp = %p)\n", (void *)mp);

	if (!prison_allow(td->td_ucred, PR_ALLOW_MOUNT_CRYPTOFS))
		return (EPERM);
	if (mp->mnt_flag & MNT_ROOTFS)
		return (EOPNOTSUPP);

	/*
	 * Update is a no-op
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		/*
		 * Only support update mounts for NFS export.
		 */
		if (vfs_flagopt(mp->mnt_optnew, "export", NULL, 0))
			return (0);
		else
			return (EOPNOTSUPP);
	}

	/*
	 * Get argument
	 */
	error = vfs_getopt(mp->mnt_optnew, "target", (void **)&target, &len);
	if (error || target[len - 1] != '\0')
		return (EINVAL);

	/*
	 * Unlock lower node to avoid possible deadlock.
	 */
	if ((mp->mnt_vnodecovered->v_op == &crypto_vnodeops) &&
	    VOP_ISLOCKED(mp->mnt_vnodecovered) == LK_EXCLUSIVE) {
		VOP_UNLOCK(mp->mnt_vnodecovered, 0);
		isvnunlocked = 1;
	}
	/*
	 * Find lower node
	 */
	NDINIT(ndp, LOOKUP, FOLLOW|LOCKLEAF, UIO_SYSSPACE, target, curthread);
	error = namei(ndp);

	/*
	 * Re-lock vnode.
	 * XXXKIB This is deadlock-prone as well.
	 */
	if (isvnunlocked)
		vn_lock(mp->mnt_vnodecovered, LK_EXCLUSIVE | LK_RETRY);

	if (error)
		return (error);
	NDFREE(ndp, NDF_ONLY_PNBUF);

	/*
	 * Sanity check on lower vnode
	 */
	lowerrootvp = ndp->ni_vp;

	/*
	 * Check multi crypto.mount to avoid `lock against myself' panic.
	 */
	if (lowerrootvp == VTOCRYPTO(mp->mnt_vnodecovered)->crypto_lowervp) {
		CRYPTOFSDEBUG("crypto.s_mount: multi crypto.mount?\n");
		vput(lowerrootvp);
		return (EDEADLK);
	}

	xmp = (struct crypto_mount *) malloc(sizeof(struct crypto_mount),
	    M_CRYPTOFSMNT, M_WAITOK | M_ZERO);

	/*
	 * Save reference to underlying FS
	 */
	xmp->crypto._vfs = lowerrootvp->v_mount;

	/*
	 * Save reference.  Each mount also holds
	 * a reference on the root vnode.
	 */
	error = crypto_nodeget(mp, lowerrootvp, &vp);
	/*
	 * Make sure the node alias worked
	 */
	if (error) {
		free(xmp, M_CRYPTOFSMNT);
		return (error);
	}

	/*
	 * Keep a held reference to the root vnode.
	 * It is vrele'd in crypto.s_unmount.
	 */
	crypto._rootvp = vp;
	crypto._rootvp->v_vflag |= VV_ROOT;
	xmp->crypto._rootvp = crypto._rootvp;

	/*
	 * Unlock the node (either the lower or the alias)
	 */
	VOP_UNLOCK(vp, 0);

	if (CRYPTOVPTOLOWERVP(crypto._rootvp)->v_mount->mnt_flag & MNT_LOCAL) {
		MNT_ILOCK(mp);
		mp->mnt_flag |= MNT_LOCAL;
		MNT_IUNLOCK(mp);
	}

	xmp->crypto._flags |= CRYPTOM_CACHE;
	if (vfs_getopt(mp->mnt_optnew, "nocache", NULL, NULL) == 0)
		xmp->crypto._flags &= ~CRYPTOM_CACHE;

	MNT_ILOCK(mp);
	if ((xmp->crypto._flags & CRYPTOM_CACHE) != 0) {
		mp->mnt_kern_flag |= lowerrootvp->v_mount->mnt_kern_flag &
		    (MNTK_SHARED_WRITES | MNTK_LOOKUP_SHARED |
		    MNTK_EXTENDED_SHARED);
	}
	mp->mnt_kern_flag |= MNTK_LOOKUP_EXCL_DOTDOT;
	mp->mnt_kern_flag |= lowerrootvp->v_mount->mnt_kern_flag &
	    MNTK_USES_BCACHE;
	MNT_IUNLOCK(mp);
	mp->mnt_data = xmp;
	vfs_getnewfsid(mp);
	if ((xmp->crypto._flags & CRYPTOM_CACHE) != 0) {
		MNT_ILOCK(xmp->crypto._vfs);
		TAILQ_INSERT_TAIL(&xmp->crypto._vfs->mnt_uppers, mp,
		    mnt_upper_link);
		MNT_IUNLOCK(xmp->crypto._vfs);
	}

	vfs_mountedfrom(mp, target);

	CRYPTOFSDEBUG("crypto.s_mount: lower %s, alias at %s\n",
		mp->mnt_stat.f_mntfromname, mp->mnt_stat.f_mntonname);
	return (0);
}

/*
 * Free reference to crypto.layer
 */
static int
crypto.s_unmount(mp, mntflags)
	struct mount *mp;
	int mntflags;
{
	struct crypto_mount *mntdata;
	struct mount *ump;
	int error, flags;

	CRYPTOFSDEBUG("crypto.s_unmount: mp = %p\n", (void *)mp);

	if (mntflags & MNT_FORCE)
		flags = FORCECLOSE;
	else
		flags = 0;

	/* There is 1 extra root vnode reference (crypto._rootvp). */
	error = vflush(mp, 1, flags, curthread);
	if (error)
		return (error);

	/*
	 * Finally, throw away the crypto_mount structure
	 */
	mntdata = mp->mnt_data;
	ump = mntdata->crypto._vfs;
	if ((mntdata->crypto._flags & CRYPTOM_CACHE) != 0) {
		MNT_ILOCK(ump);
		while ((ump->mnt_kern_flag & MNTK_VGONE_UPPER) != 0) {
			ump->mnt_kern_flag |= MNTK_VGONE_WAITER;
			msleep(&ump->mnt_uppers, &ump->mnt_mtx, 0, "vgnupw", 0);
		}
		TAILQ_REMOVE(&ump->mnt_uppers, mp, mnt_upper_link);
		MNT_IUNLOCK(ump);
	}
	mp->mnt_data = NULL;
	free(mntdata, M_CRYPTOFSMNT);
	return (0);
}

static int
crypto.s_root(mp, flags, vpp)
	struct mount *mp;
	int flags;
	struct vnode **vpp;
{
	struct vnode *vp;

	CRYPTOFSDEBUG("crypto.s_root(mp = %p, vp = %p->%p)\n", (void *)mp,
	    (void *)MOUNTTOCRYPTOMOUNT(mp)->crypto._rootvp,
	    (void *)CRYPTOVPTOLOWERVP(MOUNTTOCRYPTOMOUNT(mp)->crypto._rootvp));

	/*
	 * Return locked reference to root.
	 */
	vp = MOUNTTOCRYPTOMOUNT(mp)->crypto._rootvp;
	VREF(vp);

	ASSERT_VOP_UNLOCKED(vp, "root vnode is locked");
	vn_lock(vp, flags | LK_RETRY);
	*vpp = vp;
	return 0;
}

static int
crypto.s_quotactl(mp, cmd, uid, arg)
	struct mount *mp;
	int cmd;
	uid_t uid;
	void *arg;
{
	return VFS_QUOTACTL(MOUNTTOCRYPTOMOUNT(mp)->crypto._vfs, cmd, uid, arg);
}

static int
crypto.s_statfs(mp, sbp)
	struct mount *mp;
	struct statfs *sbp;
{
	int error;
	struct statfs mstat;

	CRYPTOFSDEBUG("crypto.s_statfs(mp = %p, vp = %p->%p)\n", (void *)mp,
	    (void *)MOUNTTOCRYPTOMOUNT(mp)->crypto._rootvp,
	    (void *)CRYPTOVPTOLOWERVP(MOUNTTOCRYPTOMOUNT(mp)->crypto._rootvp));

	bzero(&mstat, sizeof(mstat));

	error = VFS_STATFS(MOUNTTOCRYPTOMOUNT(mp)->crypto._vfs, &mstat);
	if (error)
		return (error);

	/* now copy across the "interesting" information and fake the rest */
	sbp->f_type = mstat.f_type;
	sbp->f_flags = (sbp->f_flags & (MNT_RDONLY | MNT_NOEXEC | MNT_NOSUID |
	    MNT_UNION | MNT_NOSYMFOLLOW)) | (mstat.f_flags & ~MNT_ROOTFS);
	sbp->f_bsize = mstat.f_bsize;
	sbp->f_iosize = mstat.f_iosize;
	sbp->f_blocks = mstat.f_blocks;
	sbp->f_bfree = mstat.f_bfree;
	sbp->f_bavail = mstat.f_bavail;
	sbp->f_files = mstat.f_files;
	sbp->f_ffree = mstat.f_ffree;
	return (0);
}

static int
crypto.s_sync(mp, waitfor)
	struct mount *mp;
	int waitfor;
{
	/*
	 * XXX - Assumes no data cached at crypto.layer.
	 */
	return (0);
}

static int
crypto.s_vget(mp, ino, flags, vpp)
	struct mount *mp;
	ino_t ino;
	int flags;
	struct vnode **vpp;
{
	int error;

	KASSERT((flags & LK_TYPE_MASK) != 0,
	    ("crypto.s_vget: no lock requested"));

	error = VFS_VGET(MOUNTTOCRYPTOMOUNT(mp)->crypto._vfs, ino, flags, vpp);
	if (error != 0)
		return (error);
	return (crypto_nodeget(mp, *vpp, vpp));
}

static int
crypto.s_fhtovp(mp, fidp, flags, vpp)
	struct mount *mp;
	struct fid *fidp;
	int flags;
	struct vnode **vpp;
{
	int error;

	error = VFS_FHTOVP(MOUNTTOCRYPTOMOUNT(mp)->crypto._vfs, fidp, flags,
	    vpp);
	if (error != 0)
		return (error);
	return (crypto_nodeget(mp, *vpp, vpp));
}

static int                        
crypto.s_extattrctl(mp, cmd, filename_vp, namespace, attrname)
	struct mount *mp;
	int cmd;
	struct vnode *filename_vp;
	int namespace;
	const char *attrname;
{

	return (VFS_EXTATTRCTL(MOUNTTOCRYPTOMOUNT(mp)->crypto._vfs, cmd,
	    filename_vp, namespace, attrname));
}

static void
crypto.s_reclaim_lowervp(struct mount *mp, struct vnode *lowervp)
{
	struct vnode *vp;

	vp = crypto_hashget(mp, lowervp);
	if (vp == NULL)
		return;
	VTOCRYPTO(vp)->crypto_flags |= CRYPTOV_NOUNLOCK;
	vgone(vp);
	vput(vp);
}

static void
crypto.s_unlink_lowervp(struct mount *mp, struct vnode *lowervp)
{
	struct vnode *vp;
	struct crypto_node *xp;

	vp = crypto_hashget(mp, lowervp);
	if (vp == NULL)
		return;
	xp = VTOCRYPTO(vp);
	xp->crypto_flags |= CRYPTOV_DROP | CRYPTOV_NOUNLOCK;
	vhold(vp);
	vunref(vp);

	if (vp->v_usecount == 0) {
		/*
		 * If vunref() dropped the last use reference on the
		 * crypto.s vnode, it must be reclaimed, and its lock
		 * was split from the lower vnode lock.  Need to do
		 * extra unlock before allowing the final vdrop() to
		 * free the vnode.
		 */
		KASSERT((vp->v_iflag & VI_DOOMED) != 0,
		    ("not reclaimed crypto.s vnode %p", vp));
		VOP_UNLOCK(vp, 0);
	} else {
		/*
		 * Otherwise, the crypto.s vnode still shares the lock
		 * with the lower vnode, and must not be unlocked.
		 * Also clear the CRYPTOV_NOUNLOCK, the flag is not
		 * relevant for future reclamations.
		 */
		ASSERT_VOP_ELOCKED(vp, "unlink_lowervp");
		KASSERT((vp->v_iflag & VI_DOOMED) == 0,
		    ("reclaimed crypto.s vnode %p", vp));
		xp->crypto_flags &= ~CRYPTOV_NOUNLOCK;
	}
	vdrop(vp);
}

static struct vfsops crypto_vfsops = {
	.vfs_extattrctl =	crypto.s_extattrctl,
	.vfs_fhtovp =		crypto.s_fhtovp,
	.vfs_init =		crypto.s_init,
	.vfs_mount =		crypto.s_mount,
	.vfs_quotactl =		crypto.s_quotactl,
	.vfs_root =		crypto.s_root,
	.vfs_statfs =		crypto.s_statfs,
	.vfs_sync =		crypto.s_sync,
	.vfs_uninit =		crypto.s_uninit,
	.vfs_unmount =		crypto.s_unmount,
	.vfs_vget =		crypto.s_vget,
	.vfs_reclaim_lowervp =	crypto.s_reclaim_lowervp,
	.vfs_unlink_lowervp =	crypto.s_unlink_lowervp,
};

VFS_SET(crypto_vfsops, crypto.s, VFCF_LOOPBACK | VFCF_JAIL);
