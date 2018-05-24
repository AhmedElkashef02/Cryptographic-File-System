/*
 * This code calls the encryption and decryption functions that in turn 
 * uses the Rijndael (AES) cipher.  The key length is hard-coded to 128 
 * key bits; this number may be changed by redefining a constant near 
 * the start of the file.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vnode.h>

#include "rijndael.h"
#include "encrypt.c"

