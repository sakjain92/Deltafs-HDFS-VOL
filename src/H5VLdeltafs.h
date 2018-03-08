/*
 * Programmer:  Saksham Jain <sakshamj@andrew.cmu.edu>
 *              March, 2017
 *
 * Purpose:	The private header file for the Deltafs VOL plugin.
 */
#ifndef H5VLdeltafs_H
#define H5VLdeltafs_H

/* Include package's public header */
#include "H5VLdeltafs_public.h"
#include "H5VLprivate.h"

#include "deltafs_api.h"

#define HDF5_VOL_DELTAFS_VERSION_1	1	/* Version number of VOL plugin */

#ifdef __cplusplus
extern "C" {
#endif

H5_DLL hbool_t H5VL_deltafs_is_enabled(void);
H5_DLL herr_t H5VL_deltafs_set_plugin_prop(H5VL_plugin_prop_t *vol_prop);

#ifdef __cplusplus
}
#endif

#endif /* H5VLdeltafs_H */
