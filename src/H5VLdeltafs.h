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
#define HDF5_VOL_DELTAFS_MAX_NAME   32  /* Max number of character in group/dataset/file name */
#define HDF5_VOL_DELTAFS_MAX_DATASET    8   /* Max dataset in a group */
#define HDF5_VOL_DELTAFS_MAX_GROUP      8   /* Max groups in a file */

#define HDF5_VOL_DELATFS_FILE_MAGIC_NUMBER  (size_t)0xAA55AA55

#ifdef __cplusplus
extern "C" {
#endif

/* Common object and attribute information */
typedef struct H5VL_deltafs_item_t {
    H5I_type_t type;
    struct H5VL_deltafs_file_t *file;
} H5VL_deltafs_item_t;

/* Common object information */
typedef struct H5VL_deltafs_obj_t {
    H5VL_deltafs_item_t item; /* Must be first */
} H5VL_deltafs_obj_t;

/* The dataset metadata stored in a delta file */
typedef struct H5VL_deltafs_dmd_t {
    char name[HDF5_VOL_DELTAFS_MAX_NAME];
    size_t offset;                          /* Offset in file */
    size_t size;                            /* Total size of data */
    size_t type_size;
    size_t space_size;
} H5VL_deltafs_dmd_t;

/* The group metadata stored in deltafs file */
typedef struct H5VL_deltafs_gmd_t {
    char name[HDF5_VOL_DELTAFS_MAX_NAME];
    H5VL_deltafs_dmd_t dmd[HDF5_VOL_DELTAFS_MAX_DATASET];
    size_t num_dsets;
} H5VL_deltafs_gmd_t;

/* The file metadata stored in deltafs file */
typedef struct H5VL_deltafs_fmd_t {
    size_t num_groups;
    size_t write_offset;                    /* Offset where to write next */
    H5VL_deltafs_gmd_t gmd[HDF5_VOL_DELTAFS_MAX_GROUP];
    size_t magic_number;            /* Magic number to check the consistency */
} H5VL_deltafs_fmd_t;

/* The dataset struct */
typedef struct H5VL_deltafs_dset_t {
    H5VL_deltafs_obj_t obj;                 /* Must be first */
    struct H5VL_deltafs_dset_t *lnext;               /* Link for list */
    hbool_t dirty;
    hid_t type_id;
    hid_t space_id;
    size_t didx;
    size_t gidx;
    char *buf;
    size_t buf_size;
    hbool_t is_buf_read;                     /* Has data been read into buf? */
    size_t rc;
    H5VL_deltafs_dmd_t *dmd;
} H5VL_deltafs_dset_t;

/* The group struct */
typedef struct H5VL_deltafs_group_t {
    H5VL_deltafs_obj_t obj;                 /* Must be first */
    size_t index;
} H5VL_deltafs_group_t;

/* Define head */
typedef struct H5VL_deltafs_lhead_t {
    H5VL_deltafs_dset_t *head;
    H5VL_deltafs_dset_t *tail;
} H5VL_deltafs_lhead_t;

/* The file struct */
typedef struct H5VL_deltafs_file_t {
    H5VL_deltafs_obj_t obj;                 /* Must be first */
    unsigned flags;
    H5VL_deltafs_lhead_t dlist_head;              /* Dirty dataset list */
    hbool_t dirty;
    int fd;
    H5VL_deltafs_fmd_t fmd;
} H5VL_deltafs_file_t;

/* Macros for list */
#define H5VL_DELTAFS_LHEAD_INIT(h)      \
{                                       \
    (h).head = NULL;                    \
    (h).tail = NULL;                    \
}

#define H5VL_DELTAFS_LELEM_INIT(e)      {(e)->lnext = NULL;}
#define H5VL_DELTAFS_LGET_FRONT(h)      ((h).head)
#define H5VL_DELTAFS_LADD_TAIL(h, e)    \
{                                       \
    if ((h).head != NULL) {             \
        (h).tail->lnext = (e);          \
        (h).tail = (e);                 \
    } else {                            \
        (h).head = (h).tail = (e);      \
    }                                   \
    (e)->lnext = NULL;                  \
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
