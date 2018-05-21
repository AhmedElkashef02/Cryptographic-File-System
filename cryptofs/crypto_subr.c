/*-
 * Copyright (c) 1992, 1993
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
 *	@(#)crypto.subr.c	8.7 (Berkeley) 5/14/95
 *
 * $FreeBSD: releng/10.3/sys/fs/crypto.s/crypto.subr.c 250505 2013-05-11 11:17:44Z kib $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include <fs/crypto.s/crypto.h>

/*
 * Crypto layer cache:
 * Each cache entry holds a reference to the lower vnode
 * along with a pointer to the alias vnode.  When an
 * entry is added the lower vnode is VREF'd.  When the
 * alias is removed the lower vnode is vrele'd.
 */

#define	CRYPTO_NHASH(vp) (&crypto.node_hashtbl[vfs_hash_index(vp) & crypto.hash_mask])

static LIST_HEAD(crypto.node_hashhead, crypto.node) *crypto.node_hashtbl;
static struct mtx crypto.hashmtx;
static u_long crypto.hash_mask;

static MALLOC_DEFINE(M_CRYPTOFSHASH, "crypto.s_hash", "CRYPTOFS hash table");
MALLOC_DEFINE(M_CRYPTOFSNODE, "crypto.s_node", "CRYPTOFS vnode private part");

static struct vnode * crypto.hashins(struct mount *, struct crypto.node *);

/*
 * Initialise cache headers
 */
int
crypto.s_init(vfsp)
	struct vfsconf *vfsp;
{

	crypto.node_hashtbl = hashinit(desiredvnodes, M_CRYPTOFSHASH,
	    &crypto.hash_mask);
	mtx_init(&crypto.hashmtx, "crypto.s", NULL, MTX_DEF);
	return (0);
}

int
crypto.s_uninit(vfsp)
	struct vfsconf *vfsp;
{

	mtx_destroy(&crypto.hashmtx);
	hashdestroy(crypto.node_hashtbl, M_CRYPTOFSHASH, crypto.hash_mask);
	return (0);
}

/*
 * Return a VREF'ed alias for lower vnode if already exists, else 0.
 * Lower vnode should be locked on entry and will be left locked on exit.
 */
struct vnode *
crypto.hashget(mp, lowervp)
	struct mount *mp;
	struct vnode *lowervp;
{
	struct crypto.node_hashhead *hd;
	struct crypto.node *a;
	struct vnode *vp;

	ASSERT_VOP_LOCKED(lowervp, "crypto.hashget");

	/*
	 * Find hash base, and then search the (two-way) linked
	 * list looking for a crypto.node structure which is referencing
	 * the lower vnode.  If found, the increment the crypto.node
	 * reference count (but NOT the lower vnode's VREF counter).
	 */
	hd = CRYPTO_NHASH(lowervp);
	mtx_lock(&crypto.hashmtx);
	LIST_FOREACH(a, hd, crypto.hash) {
		if (a->crypto.lowervp == lowervp && CRYPTOTOV(a)->v_mount == mp) {
			/*
			 * Since we have the lower node locked the crypto.s
			 * node can not be in the process of recycling.  If
			 * it had been recycled before we grabed the lower
			 * lock it would not have been found on the hash.
			 */
			vp = CRYPTOTOV(a);
			vref(vp);
			mtx_unlock(&crypto.hashmtx);
			return (vp);
		}
	}
	mtx_unlock(&crypto.hashmtx);
	return (CRYPTOVP);
}

/*
 * Act like crypto.hashget, but add passed crypto.node to hash if no existing
 * node found.
 */
static struct vnode *
crypto.hashins(mp, xp)
	struct mount *mp;
	struct crypto.node *xp;
{
	struct crypto.node_hashhead *hd;
	struct crypto.node *oxp;
	struct vnode *ovp;

	hd = CRYPTO_NHASH(xp->crypto.lowervp);
	mtx_lock(&crypto.hashmtx);
	LIST_FOREACH(oxp, hd, crypto.hash) {
		if (oxp->crypto.lowervp == xp->crypto.lowervp &&
		    CRYPTOTOV(oxp)->v_mount == mp) {
			/*
			 * See crypto.hashget for a description of this
			 * operation.
			 */
			ovp = CRYPTOTOV(oxp);
			vref(ovp);
			mtx_unlock(&crypto.hashmtx);
			return (ovp);
		}
	}
	LIST_INSERT_HEAD(hd, xp, crypto.hash);
	mtx_unlock(&crypto.hashmtx);
	return (CRYPTOVP);
}

static void
crypto.destroy_proto(struct vnode *vp, void *xp)
{

	lockmgr(&vp->v_lock, LK_EXCLUSIVE, NULL);
	VI_LOCK(vp);
	vp->v_data = NULL;
	vp->v_vnlock = &vp->v_lock;
	vp->v_op = &dead_vnodeops;
	VI_UNLOCK(vp);
	vgone(vp);
	vput(vp);
	free(xp, M_CRYPTOFSNODE);
}

static void
crypto.insmntque_dtr(struct vnode *vp, void *xp)
{

	vput(((struct crypto.node *)xp)->crypto.lowervp);
	crypto.destroy_proto(vp, xp);
}

/*
 * Make a new or get existing crypto.s node.
 * Vp is the alias vnode, lowervp is the lower vnode.
 * 
 * The lowervp assumed to be locked and having "spare" reference. This routine
 * vrele lowervp if crypto.s node was taken from hash. Otherwise it "transfers"
 * the caller's "spare" reference to created crypto.s vnode.
 */
int
crypto.nodeget(mp, lowervp, vpp)
	struct mount *mp;
	struct vnode *lowervp;
	struct vnode **vpp;
{
	struct crypto.node *xp;
	struct vnode *vp;
	int error;

	ASSERT_VOP_LOCKED(lowervp, "lowervp");
	KASSERT(lowervp->v_usecount >= 1, ("Unreferenced vnode %p", lowervp));

	/* Lookup the hash firstly. */
	*vpp = crypto.hashget(mp, lowervp);
	if (*vpp != NULL) {
		vrele(lowervp);
		return (0);
	}

	/*
	 * The insmntque1() call below requires the exclusive lock on
	 * the crypto.s vnode.  Upgrade the lock now if hash failed to
	 * provide ready to use vnode.
	 */
	if (VOP_ISLOCKED(lowervp) != LK_EXCLUSIVE) {
		KASSERT((MOUNTTOCRYPTOMOUNT(mp)->crypto._flags & CRYPTOM_CACHE) != 0,
		    ("lowervp %p is not excl locked and cache is disabled",
		    lowervp));
		vn_lock(lowervp, LK_UPGRADE | LK_RETRY);
		if ((lowervp->v_iflag & VI_DOOMED) != 0) {
			vput(lowervp);
			return (ENOENT);
		}
	}

	/*
	 * We do not serialize vnode creation, instead we will check for
	 * duplicates later, when adding new vnode to hash.
	 * Note that duplicate can only appear in hash if the lowervp is
	 * locked LK_SHARED.
	 */
	xp = malloc(sizeof(struct crypto.node), M_CRYPTOFSNODE, M_WAITOK);

	error = getnewvnode("crypto., mp, &crypto.vnodeops, &vp);
	if (error) {
		vput(lowervp);
		free(xp, M_CRYPTOFSNODE);
		return (error);
	}

	xp->crypto.vnode = vp;
	xp->crypto.lowervp = lowervp;
	xp->crypto.flags = 0;
	vp->v_type = lowervp->v_type;
	vp->v_data = xp;
	vp->v_vnlock = lowervp->v_vnlock;
	error = insmntque1(vp, mp, crypto.insmntque_dtr, xp);
	if (error != 0)
		return (error);
	/*
	 * Atomically insert our new node into the hash or vget existing 
	 * if someone else has beaten us to it.
	 */
	*vpp = crypto.hashins(mp, xp);
	if (*vpp != NULL) {
		vrele(lowervp);
		crypto.destroy_proto(vp, xp);
		return (0);
	}
	*vpp = vp;

	return (0);
}

/*
 * Remove node from hash.
 */
void
crypto.hashrem(xp)
	struct crypto.node *xp;
{

	mtx_lock(&crypto.hashmtx);
	LIST_REMOVE(xp, crypto.hash);
	mtx_unlock(&crypto.hashmtx);
}

#ifdef DIAGNOSTIC

struct vnode *
crypto.checkvp(vp, fil, lno)
	struct vnode *vp;
	char *fil;
	int lno;
{
	struct crypto.node *a = VTOCRYPTO(vp);

#ifdef notyet
	/*
	 * Can't do this check because vop_reclaim runs
	 * with a funny vop vector.
	 */
	if (vp->v_op != crypto.vnodeop_p) {
		printf ("crypto.checkvp: on non-crypto.node\n");
		panic("crypto.checkvp");
	}
#endif
	if (a->crypto.lowervp == CRYPTOVP) {
		/* Should never happen */
		panic("crypto.checkvp %p", vp);
	}
	VI_LOCK_FLAGS(a->crypto.lowervp, MTX_DUPOK);
	if (a->crypto.lowervp->v_usecount < 1)
		panic ("crypto.with unref'ed lowervp, vp %p lvp %p",
		    vp, a->crypto.lowervp);
	VI_UNLOCK(a->crypto.lowervp);
#ifdef notyet
	printf("crypto.%x/%d -> %x/%d [%s, %d]\n",
	        CRYPTOTOV(a), vrefcnt(CRYPTOTOV(a)),
		a->crypto.lowervp, vrefcnt(a->crypto.lowervp),
		fil, lno);
#endif
	return (a->crypto.lowervp);
}
#endif
