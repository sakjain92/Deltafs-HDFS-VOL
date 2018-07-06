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

#define HDF5_VOL_DELTAFS_VERSION_1	    1	    /* Version number of VOL plugin */
#define HDF5_VOL_DELTAFS_MAX_NAME       256     /* Max number of character in group/dataset/file name */
#define HDF5_VOL_DELTAFS_MD_FNAME       "HDF5_MD"   /* Metadata filename */

/* TODO: Remove this limitation */
#define HDF5_VOL_DELTAFS_MAX_DATASET    32      /* Max dataset in a group */


#ifdef __cplusplus
extern "C" {
#endif

/* Common object and attribute information */
typedef struct H5VL_deltafs_item_t {
    H5I_type_t type;
    struct H5VL_deltafs_file_t *file;
    int rc;
} H5VL_deltafs_item_t;

/* Common object information */
typedef struct H5VL_deltafs_obj_t {
    H5VL_deltafs_item_t item; /* Must be first */
} H5VL_deltafs_obj_t;

/* The dataset metadata stored in a delta file */
typedef struct H5VL_deltafs_dmd_t {
    char name[HDF5_VOL_DELTAFS_MAX_NAME + 1];
    hid_t type_id;
    char *type_buf;
    size_t type_buf_size;
    hbool_t is_initialized;
} H5VL_deltafs_dmd_t;

/* The file metadata stored in deltafs file */
typedef struct H5VL_deltafs_fmd_t {
    size_t total_ranks;                 /* Total number of process */
    size_t num_groups;
    size_t num_datasets;
    hbool_t is_datasets_finalized;      /* Have the num of datasets fixed */
    H5VL_deltafs_dmd_t dmd[HDF5_VOL_DELTAFS_MAX_DATASET];
} H5VL_deltafs_fmd_t;

/* The dataset struct */
typedef struct H5VL_deltafs_dset_t {
    H5VL_deltafs_obj_t obj;                 /* Must be first */
    char name[HDF5_VOL_DELTAFS_MAX_NAME + 1];
    struct H5VL_deltafs_group_t *parent_grp;
    size_t index;
    H5VL_deltafs_dmd_t *dmd;

} H5VL_deltafs_dset_t;

/* The group struct */
typedef struct H5VL_deltafs_group_t {
    H5VL_deltafs_obj_t obj;                 /* Must be first */
    size_t index;
    size_t num_datasets;
    size_t num_elems;

    char *buf;
    size_t buf_filled_len;                  /* How much has buffer been written */
    size_t buf_size;
    hbool_t is_read;                        /* Has group buffer been read ? */
    hbool_t dirty;

} H5VL_deltafs_group_t;

/* The file struct */
typedef struct H5VL_deltafs_file_t {
    H5VL_deltafs_obj_t obj;                 /* Must be first */
    char name[HDF5_VOL_DELTAFS_MAX_NAME + 1];
    unsigned flags;
    H5VL_deltafs_fmd_t fmd;
    deltafs_plfsdir_t *fmd_handle;
    
    int rank;                               /* MPI rank of process */
    size_t max_grp_buf_size;                /* Max allocated buffer size of grp */

    hbool_t is_open;                        /* File can be opened once only at a time */
    hbool_t dirty;

    /* Link list */
    struct H5VL_deltafs_file_t *lnext;
    struct H5VL_deltafs_file_t *lprev;
} H5VL_deltafs_file_t;

/* Define head for files */
typedef struct H5VL_deltafs_fhead {
    H5VL_deltafs_file_t *head;
    H5VL_deltafs_file_t *tail;
} H5VL_deltafs_fhead_t;

/* Struct for deltafs scanner callback arg */
typedef struct H5VL_deltafs_cb_arg {

    hbool_t fail;                           /* Has the callback failed? */
    hsize_t elem_size;
    H5VL_deltafs_group_t *grp;
    hsize_t count;
    
} H5VL_deltafs_cb_arg_t;

/* Macros for list */
#define H5VL_DELTAFS_LHEAD_INIT(h)      \
{                                       \
    (h).head = NULL;                    \
    (h).tail = NULL;                    \
}

#define H5VL_DELTAFS_LELEM_INIT(e)      {(e)->lnext = NULL; (e)->lprev = NULL;}
#define H5VL_DELTAFS_LGET_FRONT(h)      ((h).head)
#define H5VL_DELTAFS_LGET_END(h)        ((h).tail)
#define H5VL_DELTAFS_IS_EMPTY(h)        ((h).head == NULL)
#define H5VL_DELTAFS_LADD_TAIL(h, e)    \
{                                       \
    if ((h).head != NULL) {             \
        (h).tail->lnext = (e);          \
        (e)->lprev = (h).tail;          \
        (h).tail = (e);                 \
    } else {                            \
        (h).head = (h).tail = (e);      \
        (e)->lprev = NULL;              \
    }                                   \
    (e)->lnext = NULL;                  \
}
#define H5VL_DELTAFS_LREMOVE(h, e)              \
{                                               \
    if ((e)->lprev == NULL)                     \
        (h).head = (e)->lnext;                  \
                                                \
    if ((e)->lnext == NULL)                     \
        (h).tail = (e)->lprev;                   \
                                                \
    if ((e)->lprev != NULL)                     \
        (e)->lprev->lnext = (e)->lnext;         \
                                                \
    if ((e)->lnext != NULL)                     \
        (e)->lnext->lprev = (e)->lprev;         \
}

#define H5VL_DELTAFS_LFOR_EACH(h, elem) \
    for ((elem) = (h).head; (elem) != NULL; (elem) = (elem)->lnext)

#define H5VL_DELTAFS_LFOR_EACH_SAFE(h, elem, temp)   \
    for ((elem) = (h).head;                          \
            (elem) != NULL;                          \
            (elem) = (temp))                         \
{                                                    \
    (temp) = (elem)->lnext;                                 

#define H5VL_DELTAFS_LFOR_EACH_SAFE_END              \
}


H5_DLL hbool_t H5VL_deltafs_is_enabled(void);
H5_DLL herr_t H5VL_deltafs_set_plugin_prop(H5VL_plugin_prop_t *vol_prop);

#ifdef __cplusplus
}
#endif

#endif /* H5VLdeltafs_H */
