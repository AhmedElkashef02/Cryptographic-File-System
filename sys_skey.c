#include <sys/sysproto.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/sysent.h>

#define KEYBITS 128
#define KEYLENGTH(keybits) ((keybits)/8)

#ifndef _SYS_SYSPROTO_H_
struct skey_args {
  unsigned int k0;
  unsigned int k1;
};
#endif

int sys_skey(struct thread *td, struct skey_args *args) {
  struct ucred *cred = td->td_proc->p_ucred;    /* Get the process owner's identity. */
  uid_t id = cred->cr_uid;                      /* Get the effective user id */
  
  unsigned int k0 = args->k0;
  unsigned int k1 = args->k1;
  unsigned char key[KEYLENGTH(KEYBITS)];
  
  bzero (key, sizeof (key));
  bcopy (&k0, &(key[0]), sizeof (k0));
  bcopy (&k1, &(key[sizeof(k0)]), sizeof (k1));

  /* If k0 and k1 were 0, disable encryption and decryption */
  if (k0 == 0 && k1 == 0) {
    cred->k0 = 0;
    cred->k1 = 0;
    return 0;
  }

  /* for good compatibaility between protect file and setkey system call
   * we get k0,k1 and construct the big key, assign it to the user. */
  cred->k0 = k0;
  cred->k1 = k1;

  /* for testing */
  printf("Key = ");
  for (int i = 0; i < sizeof (key); i++) {
    printf ("%02x", key[sizeof(key)-i-1]);
  }
  printf("\nUser id = %d\n", id);

  return 0;
}
