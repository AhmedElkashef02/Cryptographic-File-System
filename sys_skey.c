#ifndef _SYSPROTO_H_

//Arguments are the two least significant integers
struct skey_args {
  unsigned int k0;
  unsigned int k1;
};
#endif

int sys_skey(struct thread *td, struct skey_args *uap) {
  struct ucred *uc;
  uc = td->td_ucred;
  
  uc->k0 = uap->k0;
  uc->k1 = uap->k1;
  
  return(0);
}
