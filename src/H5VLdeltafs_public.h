/*
 * Programmer:  Saksham Jain <sakshamj@andrew.cmu.edu>
 *              March, 2017
 *
 * Purpose:	The public header file for the DeltaFS VOL plugin.
 */
#ifndef H5VLdeltafs_public_H
#define H5VLdeltafs_public_H

/* Public headers needed by this file */
#include "H5public.h"
#include "H5Ipublic.h"

#ifdef __cplusplus
extern "C" {
#endif

H5_DLL herr_t H5VL_deltafs_init(void);

#ifdef __cplusplus
}
#endif

#endif /* H5VLdeltafs_public_H */
