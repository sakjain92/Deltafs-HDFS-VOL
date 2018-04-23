/*
 * Programmer:  Saksham Jain <sakshamj@andrew.cmu.edu>
 *              March, 2018
 *
 * Purpose: The Deltafs VOL plugin where access is forwarded to the Deltafs
 * library 
 */

#define H5O_FRIEND              /* Suppress error about including H5Opkg */

#include "H5public.h"
#include "H5private.h"

#include "H5VLdeltafs.h"
#include "H5Dprivate.h"         /* Datasets                             */
#include "H5Eprivate.h"         /* Error handling                       */
#include "H5Fprivate.h"         /* Files                                */
#include "H5FDprivate.h"        /* File drivers                         */
#include "H5Iprivate.h"         /* IDs                                  */
#include "H5MMprivate.h"        /* Memory management                    */
#include "H5Pprivate.h"         /* Property lists                       */
#include "H5Sprivate.h"         /* Dataspaces                           */
#include "H5Opkg.h"

#include "deltafs_api.h"

#define H5VL_DELTAFS_ENABLE_ENV                 "HDF5_DELTAFS_ENABLE"
#define H5VL_DELTAFS_SEQ_LIST_LEN               64
#define H5VL_DELTAFS_ROOT_GROUP_INDEX           ((size_t)(LONG_MAX))

#define H5VL_DELTAFS_FMD_NUM_GROUP_KEY          "__num_groups"
#define H5VL_DELTAFS_FMD_NUM_DATASET_KEY        "__num_datasets"
#define H5VL_DELTAFS_FMD_DATASET_NAME_KEY       "__name_datasets"
#define H5VL_DELTAFS_FMD_DATASET_TYPE_KEY       "__type_datasets"
#define H5VL_DELTAFS_FMD_MAGIC_NUMBER_KEY       "__magic_number"
#define H5VL_DELTAFS_FMD_TOTAL_RANK             "__total_rank"
#define HDF5_DELATFS_FILE_MAGIC_NUMBER          "AA55AA55"

#define H5VL_DELTAFS_H5PART_GROUPNAME_STEP	    "Step"

/* Units (in bytes) in which to increment buffer */
#define H5VL_DELTAFS_BUF_SIZE_INC               4096

/* 
 * TODO: File data and group data have constant limitations.
 * Solve these
 * TODO: The metadata being saved in files in very machine specific
 * (LE/BE dependent and machine size)
 * TODO: Support partial read/writes
 * TODO: Scatter gather io in deltafs will be helpful or modify code here
 */

/* VOL plugin value */
hid_t H5VL_DELTAFS_g = -1;
hbool_t H5VL_DELTAFS_term = false;

/* Head for the file list */
H5VL_deltafs_fhead_t H5VL_DELTAFS_fhead;

static herr_t H5VL_deltafs_term(hid_t vtpl_id);

#if 0
/* Attribute callbacks */
static void *H5VL_deltafs_attribute_create(void *_obj,
    H5VL_loc_params_t loc_params, const char *name, hid_t acpl_id,
    hid_t aapl_id, hid_t dxpl_id, void **req);
static void *H5VL_deltafs_attribute_open(void *_obj, H5VL_loc_params_t loc_params,
    const char *name, hid_t aapl_id, hid_t dxpl_id, void **req);
static herr_t H5VL_deltafs_attribute_read(void *_attr, hid_t mem_type_id,
    void *buf, hid_t dxpl_id, void **req);
static herr_t H5VL_deltafs_attribute_write(void *_attr, hid_t mem_type_id,
    const void *buf, hid_t dxpl_id, void **req);
static herr_t H5VL_deltafs_attribute_close(void *_attr, hid_t dxpl_id,
    void **req);
#endif

/* Dataset callbacks */
static void *H5VL_deltafs_dataset_create(void *_item,
    H5VL_loc_params_t loc_params, const char *name, hid_t dcpl_id,
    hid_t dapl_id, hid_t dxpl_id, void **req);
static void *H5VL_deltafs_dataset_open(void *_item, H5VL_loc_params_t loc_params,
    const char *name, hid_t dapl_id, hid_t dxpl_id, void **req);
static herr_t H5VL_deltafs_dataset_read(void *_dset, hid_t mem_type_id,
    hid_t mem_space_id, hid_t file_space_id, hid_t dxpl_id, void *buf,
    void **req);
static herr_t H5VL_deltafs_dataset_write(void *_dset, hid_t mem_type_id,
    hid_t mem_space_id, hid_t file_space_id, hid_t dxpl_id, const void *buf,
    void **req);
static herr_t
H5VL_deltafs_dataset_get(void *_dset, H5VL_dataset_get_t get_type, 
    hid_t dxpl_id, void **req, va_list arguments);
static herr_t H5VL_deltafs_dataset_close(void *_dset, hid_t dxpl_id, void **req);

/* File callbacks */
static void *H5VL_deltafs_file_create(const char *name, unsigned flags,
    hid_t fcpl_id, hid_t fapl_id, hid_t dxpl_id, void **req);
static void *H5VL_deltafs_file_open(const char *name, unsigned flags,
    hid_t fapl_id, hid_t dxpl_id, void **req);
static herr_t H5VL_deltafs_file_close(void *_file, hid_t dxpl_id, void **req);

/* Group callbacks */
static void *H5VL_deltafs_group_create(void *_item, H5VL_loc_params_t loc_params,
    const char *name, hid_t gcpl_id, hid_t gapl_id, hid_t dxpl_id, void **req);
static void *H5VL_deltafs_group_open(void *_item, H5VL_loc_params_t loc_params,
    const char *name, hid_t gapl_id, hid_t dxpl_id, void **req);
static herr_t H5VL_deltafs_group_close(void *_grp, hid_t dxpl_id, void **req);

/* Link callbacks */
static herr_t H5VL_deltafs_link_specific(void *_item, H5VL_loc_params_t loc_params,
    H5VL_link_specific_t specific_type, hid_t dxpl_id, void **req,
    va_list arguments);

/* Object Callbacks */
static void * H5VL_deltafs_object_open(void *_item, H5VL_loc_params_t loc_params, 
    H5I_type_t *opened_type, hid_t dxpl_id, void **req);
static herr_t H5VL_deltafs_object_optional(void *_item, hid_t dxpl_id, void **req,
    va_list arguments);
static herr_t H5VL_deltafs_object_close(void *_obj, hid_t dxpl_id, void **req);

/* Helper functions */
static herr_t H5VL_deltafs_file_close_helper(H5VL_deltafs_file_t *file);
static herr_t H5VL_deltafs_dataset_close_helper(H5VL_deltafs_dset_t *dset);
static herr_t H5VL_deltafs_group_close_helper(H5VL_deltafs_group_t *grp);
static hbool_t H5VL_deltafs_is_root_group(H5VL_deltafs_item_t *item);

/* The Deltafs VOL plugin struct */
static H5VL_class_t H5VL_deltafs_g = {
    HDF5_VOL_DELTAFS_VERSION_1,                 /* Version number */
    H5_VOL_DELTAFS,                             /* Plugin value */
    "deltafs_vol",                              /* name */
    NULL,                                       /* initialize */
    H5VL_deltafs_term,                          /* terminate */
    0,                                          /*fapl_size */
    NULL,                                       /*fapl_copy */
    NULL,                                       /*fapl_free */

#if 0
    {                                           /* attribute_cls */
        H5VL_deltafs_attribute_create,          /* create */
        H5VL_deltafs_attribute_open,            /* open */
        H5VL_deltafs_attribute_read,            /* read */
        H5VL_deltafs_attribute_write,           /* write */
        NULL,                                   /* get */
        NULL,                                   /* specific */
        NULL,                                   /* optional */
        H5VL_deltafs_attribute_close            /* close */
    },
#else    
    {                                           /* dataset_cls */
        NULL,                                   /* create */
        NULL,                                   /* open */
        NULL,                                   /* read */
        NULL,                                   /* write */
        NULL,                                   /* get */
        NULL,                                   /* specific */
        NULL,                                   /* optional */
        NULL                                    /* close */
    },
#endif
    {                                           /* dataset_cls */
        H5VL_deltafs_dataset_create,            /* create */
        H5VL_deltafs_dataset_open,              /* open */
        H5VL_deltafs_dataset_read,              /* read */
        H5VL_deltafs_dataset_write,             /* write */
        H5VL_deltafs_dataset_get,               /* get */
        NULL,                                   /* specific */
        NULL,                                   /* optional */
        H5VL_deltafs_dataset_close              /* close */
    },
    
    {                                           /* datatype_cls */
        NULL,                                   /* commit */
        NULL,                                   /* open */
        NULL,                                   /* get */
        NULL,                                   /* specific */
        NULL,                                   /* optional */
        NULL                                    /* close */
    },

    {                                           /* file_cls */
        H5VL_deltafs_file_create,               /* create */
        H5VL_deltafs_file_open,                 /* open */
        NULL,                                   /* get */
        NULL,                                   /* specific */
        NULL,                                   /* optional */
        H5VL_deltafs_file_close                 /* close */
    },

    {                                           /* group_cls */
        H5VL_deltafs_group_create,              /* create */
        H5VL_deltafs_group_open,                /* open */
        NULL,                                   /* get */
        NULL,                                   /* specific */
        NULL,                                   /* optional */
        H5VL_deltafs_group_close                /* close */
    },

    {                                           /* link_cls */
        NULL,                                   /* create */
        NULL,                                   /* copy */
        NULL,                                   /* move */
        NULL,                                   /* get */
        H5VL_deltafs_link_specific,             /* specific */
        NULL                                    /* optional */
    },

    {                                           /* object_cls */
        H5VL_deltafs_object_open,               /* open */
        NULL,                                   /* copy */
        NULL,                                   /* get */
        NULL,                                   /* specific */
        H5VL_deltafs_object_optional            /* optional */
    },
    {
        NULL,
        NULL,
        NULL,
    },
    NULL
};

/* Free list definitions */
H5FL_DEFINE(H5VL_deltafs_file_t);
H5FL_DEFINE(H5VL_deltafs_group_t);
H5FL_DEFINE(H5VL_deltafs_dset_t);

/*-------------------------------------------------------------------------
 * Function:    H5VLdeltafs_init
 *
 * Purpose:     Initialize this vol plugin by registering the driver with the
 *              library.
 *
 * Return:      Non-negative on success/Negative on failure
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5VL_deltafs_init(void)
{
    herr_t ret_value = SUCCEED;            /* Return value */
    void *p;

    FUNC_ENTER_NOAPI(FAIL)

    /* Register the DELTAFS VOL, if it isn't already */
    if(NULL == (p = H5I_object_verify(H5VL_DELTAFS_g, H5I_VOL))) {
        if((H5VL_DELTAFS_g = H5VL_register((const H5VL_class_t *)&H5VL_deltafs_g, 
                                          sizeof(H5VL_class_t), TRUE)) < 0)
            HGOTO_ERROR(H5E_ATOM, H5E_CANTINSERT, FAIL, "can't create ID for Deltafs plugin")
    } /* end if */

    H5VL_DELTAFS_LHEAD_INIT(H5VL_DELTAFS_fhead);

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_init() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_is_enabled
 *
 * Purpose:     Checks whether deltafs has been enabled by the user
 *
 * Return:      TRUE: Deltafs enabled
 *              FALSE: Deltafs not enabled
 *
 * Programmer:  Saksham Jain
 *              March 2018
 *-------------------------------------------------------------------------
 */
hbool_t
H5VL_deltafs_is_enabled(void) {

    hbool_t ret_value = FALSE;

    FUNC_ENTER_NOAPI_NOERR

    if (H5VL_DELTAFS_term == false)
        ret_value = (NULL != HDgetenv(H5VL_DELTAFS_ENABLE_ENV));

    FUNC_LEAVE_NOAPI(ret_value)
    return ret_value;
}

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_set_plugin_prop
 *
 * Purpose:     Modifies the vol property
 *
 * Return:      SUCCEED: Deltafs initialized
 *              FAIL:    Couldn't initialize deltafs
 *
 * Programmer:  Saksham Jain
 *              March 2018
 *-------------------------------------------------------------------------
 */
herr_t
H5VL_deltafs_set_plugin_prop(H5VL_plugin_prop_t *vol_prop)
{
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI(FAIL)

    vol_prop->plugin_id = H5I_INVALID_HID;

    if (H5VL_DELTAFS_g < 0) {
        if(H5VL_deltafs_init() < 0)
            HGOTO_ERROR(H5E_FUNC, H5E_CANTINIT, FAIL, "unable to initialize Deltafs")
    }

    vol_prop->plugin_id = H5VL_DELTAFS_g;
    vol_prop->plugin_info = NULL;

done:
    FUNC_LEAVE_NOAPI(ret_value)
}


/*---------------------------------------------------------------------------
 * Function:    H5VL_deltafs_term
 *
 * Purpose:     Shut down the Deltafs VOL
 *
 * Returns:     Non-negative on success/Negative on failure
 *
 *---------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_term(hid_t H5_ATTR_UNUSED vtpl_id)
{
    H5VL_deltafs_file_t *file, *temp;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    /* Forcefully close all the open files */
    H5VL_DELTAFS_LFOR_EACH_SAFE(H5VL_DELTAFS_fhead, file, temp) {
    
        if(H5VL_deltafs_file_close_helper(file) < 0)
            HDONE_ERROR(H5E_FILE, H5E_CANTCLOSEFILE, FAIL, "can't close file");

    } H5VL_DELTAFS_LFOR_EACH_SAFE_END

    /* 
     * "Forget" plugin id.  This should normally be called by the library
     * when it is closing the id, so no need to close it here.
     */
    H5VL_DELTAFS_g = -1;
    H5VL_DELTAFS_term = true;

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_term() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_file_insert
 *
 * Purpose:     Inserts the file struct in global file list
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void
H5VL_deltafs_file_insert(H5VL_deltafs_file_t *file)
{
    
    FUNC_ENTER_NOAPI_NOINIT_NOERR

    H5VL_DELTAFS_LADD_TAIL(H5VL_DELTAFS_fhead, file);
    file->obj.item.rc++;

    FUNC_LEAVE_NOAPI_VOID
}

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_file_remove
 *
 * Purpose:     Removes the file struct from the global file list
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void
H5VL_deltafs_file_remove(H5VL_deltafs_file_t *file)
{
    
    FUNC_ENTER_NOAPI_NOINIT_NOERR

    H5VL_DELTAFS_LREMOVE(H5VL_DELTAFS_fhead, file);

    FUNC_LEAVE_NOAPI_VOID
}

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_file_find
 *
 * Purpose:     Finds file from global file list using name
 *
 * Return:      Success:        File structure or NULL
 *              Failure:        Can't open file for given flags

 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_file_find(const char *name, unsigned flags, H5VL_deltafs_file_t **filp) {

    H5VL_deltafs_file_t *file = NULL;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    H5VL_DELTAFS_LFOR_EACH(H5VL_DELTAFS_fhead, file) {

        if (strcmp(name, file->name) == 0) {

            if (file->is_open)
                HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't open file multiple times concurrently")

            if ((file->flags & H5F_ACC_WRONLY) != (flags & H5F_ACC_WRONLY))
                HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can open file for read or write only")

            /* Increase ref count */
            file->obj.item.rc++;
            *filp = file;
            break;
        }
    }

done:
    FUNC_LEAVE_NOAPI(ret_value)
}

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_read_fmd
 *
 * Purpose:     Reads the file metadata
 *
 * Return:      Success:        Fills in fmd
 *              Failure:        Can't read metadata

 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_read_fmd(H5VL_deltafs_file_t *file)
{
    deltafs_plfsdir_t *handle = NULL;
    H5VL_deltafs_fmd_t *fmd = &file->fmd;
    long long int num_groups, num_datasets, total_ranks;
    size_t size, i, keylen;
    char *value = NULL;
    char *key = NULL;
    const char *magic = HDF5_DELATFS_FILE_MAGIC_NUMBER;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    if ((handle = deltafs_plfsdir_create_handle("", O_RDONLY, 0)) == NULL)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't create deltafs handle")

    /* Rank 0 has all the metadata */
    if (deltafs_plfsdir_set_rank(handle, 0) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't set rank in deltafs handle")
 
    if (deltafs_plfsdir_open(handle, file->name) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't open rank 0 file")

    /* Get magic number */
    if ((value = (char *)deltafs_plfsdir_read(handle,
                    H5VL_DELTAFS_FMD_MAGIC_NUMBER_KEY, -1,
                    &size, NULL, NULL)) == NULL)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get magic number")

    if (strncmp(value, magic, HDstrlen(magic)))
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "magic number incorrect")

    free(value);
    value = NULL;

    /* TODO: Make these machine independent */

    /* Get total ranks */
    if ((value = (char *)deltafs_plfsdir_read(handle,
                                H5VL_DELTAFS_FMD_TOTAL_RANK, -1,
                                &size, NULL, NULL)) == NULL)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get total rank")

    /* TODO: Do more error checks */
    if ((total_ranks = strtol(value, NULL, 10)) < 0 ||
            total_ranks == LONG_MAX || total_ranks == LONG_MIN)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get total rank")

    fmd->total_ranks = (size_t)total_ranks;
    free(value);
    value = NULL;

    /* Get number of groups */
    if ((value = (char *)deltafs_plfsdir_read(handle,
                                H5VL_DELTAFS_FMD_NUM_GROUP_KEY, -1,
                                &size, NULL, NULL)) == NULL)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get number of groups")

    if ((num_groups = strtol(value, NULL, 10)) < 0 ||
            num_groups == LONG_MAX || num_groups == LONG_MIN)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get number of groups")

    fmd->num_groups = (size_t)num_groups;
    free(value);
    value = NULL;

    /* Get number of datasets */
    if ((value = (char *)deltafs_plfsdir_read(handle,
                    H5VL_DELTAFS_FMD_NUM_DATASET_KEY, -1,
                    &size, NULL, NULL)) == NULL)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get number of datasets")

    if ((num_datasets = strtol(value, NULL, 10)) < 0 ||
            num_datasets == LONG_MAX || num_datasets == LONG_MIN)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get number of datasets")

    fmd->num_datasets = (size_t)num_datasets;
    free(value);
    value = NULL;

    if (fmd->num_datasets > HDF5_VOL_DELTAFS_MAX_DATASET)
        HGOTO_ERROR(H5E_FUNC, H5E_CANTINIT, FAIL, "too many datasets")

    /* Get type and name of each datasets */
    keylen = sizeof(H5VL_DELTAFS_FMD_DATASET_NAME_KEY) +
            sizeof(H5VL_DELTAFS_FMD_DATASET_TYPE_KEY) + 33 + 1;

    if(NULL == (key = (char *)H5MM_malloc(keylen)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't allocate space for key")

    for (i = 0; i < fmd->num_datasets; i++) {
        H5VL_deltafs_dmd_t *dmd = &fmd->dmd[i];
        
        /* Get dataset name */
        snprintf(key, keylen, "%s:%ld", H5VL_DELTAFS_FMD_DATASET_NAME_KEY, i);
        if ((value = (char *)deltafs_plfsdir_read(handle, key, -1,
                                    &size, NULL, NULL)) == NULL)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get dataset name")

        if (size > HDF5_VOL_DELTAFS_MAX_NAME + 1)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "dataset name too long")

        memcpy(dmd->name, value, size);

        free(value);
        value = NULL;

        /* Get dataset type */
        snprintf(key, keylen, "%s:%ld", H5VL_DELTAFS_FMD_DATASET_TYPE_KEY, i);
        if ((value = (char *)deltafs_plfsdir_read(handle, key, -1,
                                    &size, NULL, NULL)) == NULL)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't get dataset type")

        if((dmd->type_id = H5Tdecode(value)) < 0)
            HGOTO_ERROR(H5E_ARGS, H5E_CANTDECODE, FAIL, "can't deserialize datatype")

        free(value);
        value = NULL;
        
        dmd->is_initialized = true;
    }

done:
    if (handle != NULL) {
        if (deltafs_plfsdir_free_handle(handle) < 0)
            HDONE_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't free handle")
    }

    free(value);

    H5MM_xfree(key);

    FUNC_LEAVE_NOAPI(ret_value)
}

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_write_fmd
 *
 * Purpose:     Writes the file metadata for persistence
 *
 * Return:      Success:        Wrote fmd
 *              Failure:        Can't write fmd

 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_write_fmd(H5VL_deltafs_file_t *file)
{
    deltafs_plfsdir_t *handle = file->handle;
    H5VL_deltafs_fmd_t *fmd = &file->fmd;
    size_t i, keylen, valuelen;
    char *value = NULL;
    char *key = NULL;
    const char *magic = HDF5_DELATFS_FILE_MAGIC_NUMBER;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    if (file->fmd.is_datasets_finalized == false)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "not all datasets written")

    /* Only rank 0 need to write the fmd */
    HDassert(file->rank == 0);
    HDassert(fmd->num_datasets <= HDF5_VOL_DELTAFS_MAX_DATASET);

    /* Take maximum allocation size */
    keylen = valuelen = sizeof(H5VL_DELTAFS_FMD_DATASET_NAME_KEY) +
            sizeof(H5VL_DELTAFS_FMD_DATASET_TYPE_KEY) + 33 + 1;

    if(NULL == (key = (char *)H5MM_malloc(keylen)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't allocate space for key")

    if(NULL == (value = (char *)H5MM_malloc(valuelen)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't allocate space for value")

    /* TODO: Make these machine independent */
    /* Write total rank */
    snprintf(value, valuelen, "%ld", fmd->total_ranks);
    if (deltafs_plfsdir_append(handle, H5VL_DELTAFS_FMD_TOTAL_RANK, -1, value,
                                    HDstrlen(value) + 1) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write total rank")

    /* Write number of groups */
    snprintf(value, valuelen, "%ld", fmd->num_groups);
    if (deltafs_plfsdir_append(handle, H5VL_DELTAFS_FMD_NUM_GROUP_KEY, -1, value,
                                    HDstrlen(value) + 1) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write number of groups")

    /* Write number of dataset */
    snprintf(value, valuelen, "%ld", fmd->num_datasets);
    if (deltafs_plfsdir_append(handle, H5VL_DELTAFS_FMD_NUM_DATASET_KEY, -1, value,
                                    HDstrlen(value) + 1) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write number of datasets")

    for (i = 0; i < fmd->num_datasets; i++) {

        H5VL_deltafs_dmd_t *dmd = &fmd->dmd[i];
        
        HDassert(HDstrlen(dmd->name) <= HDF5_VOL_DELTAFS_MAX_NAME);
        HDassert(dmd->is_initialized);

        /* Write dataset name */
        snprintf(key, keylen, "%s:%ld", H5VL_DELTAFS_FMD_DATASET_NAME_KEY, i);
        if (deltafs_plfsdir_append(handle, key, -1, dmd->name,
                                        HDstrlen(dmd->name) + 1) < 0)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write dataset name")

        /* Write dataset type */
        snprintf(key, keylen, "%s:%ld", H5VL_DELTAFS_FMD_DATASET_TYPE_KEY, i);
        if(deltafs_plfsdir_append(handle, key, -1, dmd->type_buf, dmd->type_buf_size) < 0)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write dataset type")

    }

    /* Write the magic number (At end) */
    if (deltafs_plfsdir_append(handle, H5VL_DELTAFS_FMD_MAGIC_NUMBER_KEY, -1,
                                magic, HDstrlen(magic) + 1) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write number of groups")

done:
    H5MM_xfree(value);

    H5MM_xfree(key);

    FUNC_LEAVE_NOAPI(ret_value)
}
/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_file_struct_init
 *
 * Purpose:     Initializes the file structure
 *
 * Return:      Success:        File structure initialized
 *              Failure:        File structure not initialized
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_file_struct_init(H5VL_deltafs_file_t *file, const char *name,
        unsigned flags)
{

    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    file->obj.item.file = file;
    file->obj.item.type = H5I_FILE;
    file->obj.item.rc = 1;
    strncpy(file->name, name, HDF5_VOL_DELTAFS_MAX_NAME);
    file->flags = flags;
    file->rank = 0;
    file->handle = NULL;
    file->max_grp_buf_size = 0;
    
    /* If file being created, file metadata needs to be written out when it closes */
    if (flags & H5F_ACC_TRUNC || flags & H5F_ACC_EXCL) {
        HDmemset(&file->fmd, 0, sizeof(file->fmd));
        file->dirty = true;
    } else {
        if (H5VL_deltafs_read_fmd(file) < 0)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't read file's metadata")

        file->fmd.is_datasets_finalized = true;
        file->dirty = false;
    }

    file->is_open = true;

    H5VL_DELTAFS_LELEM_INIT(file);
    H5VL_deltafs_file_insert(file);

done:
    FUNC_LEAVE_NOAPI(ret_value)
}

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_file_create
 *
 * Purpose:     Creates a file as a deltafs HDF5 file.
 *
 * Return:      Success:        the file id. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_file_create(const char *name, unsigned flags, hid_t fcpl_id,
    hid_t fapl_id, hid_t H5_ATTR_UNUSED dxpl_id, void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_file_t *file = NULL;
    deltafs_plfsdir_t *handle = NULL;
#ifdef H5_HAVE_PARALLEL
    MPI_Comm comm = MPI_COMM_NULL;
    MPI_Info info = MPI_INFO_NULL;
#endif
    int rank, total_ranks;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT
 
    
    if (fcpl_id != H5P_DEFAULT && fcpl_id != H5P_FILE_CREATE_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported creation properties")
    
    /*
    if (dxpl_id != H5P_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported transfer properties")
    */

    if (HDstrlen(name) > HDF5_VOL_DELTAFS_MAX_NAME)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "too long filename")

    /* Get information from the FAPL */
    if(NULL == (H5P_object_verify(fapl_id, H5P_FILE_ACCESS)))
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "not a file access property list")

    /*
     * Adjust bit flags by turning on the creation bit and making sure that
     * the EXCL or TRUNC bit is set.
     * Deltafs allows only write only or read only opening of files
     */
    if(0==(flags & (H5F_ACC_EXCL|H5F_ACC_TRUNC)))
        flags |= H5F_ACC_EXCL;      /*default*/
    
    flags = flags & ~H5F_ACC_RDWR;
    flags |= H5F_ACC_WRONLY | H5F_ACC_CREAT;

    /*
     * If file was already opened in past, return a handle to it
     */
    if (H5VL_deltafs_file_find(name, flags, &file) < 0) {
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "can't open file")
    } else if (file != NULL) {
        file->is_open = true;
        ret_value = (void *)file;
        /* XXX: Assuming that rank/comm is not changing */
        goto done;
    }

#ifdef H5_HAVE_PARALLEL
    if(H5Pget_fapl_mpio(fapl_id, &comm, &info) < 0)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "MPI comm not found")

    if (MPI_Comm_size(comm, &total_ranks) != MPI_SUCCESS)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "MPI size not found")

	if (MPI_Comm_rank (comm, &rank) != MPI_SUCCESS)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "MPI rank not found")
#else
    total_ranks = 1;
    rank = 0;
#endif

    if ((handle = deltafs_plfsdir_create_handle("", O_WRONLY, 0)) == NULL)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, NULL, "can't create deltafs handle")

    if (deltafs_plfsdir_set_rank(handle, rank) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, NULL, "can't set rank in deltafs handle")
 
    if (deltafs_plfsdir_open(handle, name) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, NULL, "can't open file")
    
    /* allocate the file object that is returned to the user */
    if (NULL == (file = H5FL_CALLOC(H5VL_deltafs_file_t)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, NULL, "can't allocate Deltafs file struct")
    
    if (H5VL_deltafs_file_struct_init(file, name, flags) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, NULL, "error in file struct init")

    file->rank = (size_t)rank;
    file->fmd.total_ranks = (size_t)total_ranks;
    file->handle = handle;

    ret_value = (void *)file;

done:
#ifdef H5_HAVE_PARALLEL
    if (MPI_COMM_NULL != comm)
        if(MPI_SUCCESS != MPI_Comm_free(&comm))
		    HDONE_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "MPI_free failed")
    
    if (MPI_INFO_NULL != info)
        if(MPI_SUCCESS != MPI_Info_free(&info))
		    HDONE_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "MPI_Info_free failed")
#endif

    /* Cleanup on failure */
    if(NULL == ret_value) {
        
        /* Close file */
        if(file) {
            if(H5VL_deltafs_file_close_helper(file) < 0)
                HDONE_ERROR(H5E_FILE, H5E_CANTCLOSEFILE, NULL, "can't close file")
        } else if(handle != NULL) {
            
            if (0 != deltafs_plfsdir_finish(handle))
                HDONE_ERROR(H5E_FILE, H5E_CLOSEERROR, NULL, "can't close file")

            if (0 != deltafs_plfsdir_free_handle(handle))
                HDONE_ERROR(H5E_FILE, H5E_CLOSEERROR, NULL, "can't close file")
        }     
    } /* end if */


    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_file_create() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_file_open
 *
 * Purpose:     Opens a file as a deltafs HDF5 file.
 *
 * Return:      Success:        the file id. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_file_open(const char *name, unsigned flags, hid_t fapl_id,
    hid_t H5_ATTR_UNUSED dxpl_id, void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_file_t *file = NULL;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /* Get information from the FAPL */
    if(NULL == H5P_object_verify(fapl_id, H5P_FILE_ACCESS))
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "not a file access property list")
    
    if (HDstrlen(name) > HDF5_VOL_DELTAFS_MAX_NAME)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "too long filename")

    /* 
     * Deltafs truncates file if opened for write. So no appends, hence
     * files can only be opened for writes
     */
    if (0 != (flags & (H5F_ACC_WRONLY | H5F_ACC_RDWR)))
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "deltafs files can only be opened for reads")
    
    /*
     * If file was already opened in past, return a handle to it
     */
    if (H5VL_deltafs_file_find(name, flags, &file) < 0) {
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "can't open file")
    } else if (file != NULL) {
        file->is_open = true;
        ret_value = file;
        goto done;
    }

    /*
    if (dxpl_id != H5P_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported creation/transfer properties")
    */

    /* allocate the file object that is returned to the user */
    if(NULL == (file = H5FL_CALLOC(H5VL_deltafs_file_t)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, NULL, "can't allocate Deltafs file struct")

    if (H5VL_deltafs_file_struct_init(file, name, flags) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, NULL, "error in file struct init")

    ret_value = (void *)file;

done:
    /* Cleanup on failure */
    if(NULL == ret_value) {
        if(file) {
            if(H5VL_deltafs_file_close_helper(file) < 0)
                HDONE_ERROR(H5E_FILE, H5E_CANTCLOSEFILE, NULL, "can't close file")
        }
    } /* end if */

    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_file_open() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_get_elem_size
 *
 * Purpose:     Gets the total size of element
 *
 * Return:      Success:        the sizeof element
 *              Failure:        FAIL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_get_elem_size(H5VL_deltafs_file_t *file, hsize_t *elem_size_p,
        hsize_t *dset_size_array)
{
    hsize_t elem_size, type_size;
    size_t i;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    if (file->fmd.is_datasets_finalized == false)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "not all datasets yet received")

    for (i = 0, elem_size = 0; i < file->fmd.num_datasets; i++) {
        if((type_size = H5Tget_size(file->fmd.dmd[i].type_id)) == 0)
            HGOTO_ERROR(H5E_DATATYPE, H5E_CANTGET, FAIL, "can't get source type size")
        
        if (dset_size_array != NULL)
            dset_size_array[i] = type_size;

        elem_size += type_size;
    }

    if (elem_size_p != NULL)
        *elem_size_p = elem_size;
done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_get_elem_size() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_file_close_helper
 *
 * Purpose:     Closes a daos-m HDF5 file.
 *
 * Return:      Success:        the file id. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_file_close_helper(H5VL_deltafs_file_t *file)
{
    size_t i;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(file);

    file->is_open = false;

    if (--file->obj.item.rc != 0)
        goto done;

    if (file->dirty && file->rank == 0 && H5VL_deltafs_write_fmd(file) < 0)
        HDONE_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write file's metadata")
    
    for (i = 0; i < file->fmd.num_datasets; i++) {
        H5VL_deltafs_dmd_t *dmd = &file->fmd.dmd[i];
        if (dmd->is_initialized && H5I_dec_app_ref(dmd->type_id) < 0)
            HDONE_ERROR(H5E_ATTR, H5E_CLOSEERROR, FAIL, "can't close type id")
        H5MM_xfree(dmd->type_buf);
    }
    
    if (file->handle != NULL) {
        if (0 != deltafs_plfsdir_finish(file->handle))
            HDONE_ERROR(H5E_FILE, H5E_CLOSEERROR, FAIL, "can't close file")

        if (0 != deltafs_plfsdir_free_handle(file->handle))
            HDONE_ERROR(H5E_FILE, H5E_CLOSEERROR, FAIL, "can't close file")
    }

    H5VL_deltafs_file_remove(file);

    file = H5FL_FREE(H5VL_deltafs_file_t, file);

done:

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_file_close_helper() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_file_close
 *
 * Purpose:     Closes a deltafs HDF5 file.
 *
 * Return:      Success:        the file id. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_file_close(void *_file, hid_t H5_ATTR_UNUSED dxpl_id,
        void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_file_t *file = (H5VL_deltafs_file_t *)_file;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(file);

    /* Close the file */
    if(H5VL_deltafs_file_close_helper(file) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTCLOSEFILE, FAIL, "can't close file")

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_file_close() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_is_root_group
 *
 * Purpose:     Checks if the group is root group
 *
 * Return:      Success:        TRUE 
 *              Failure:        FALSE
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static hbool_t
H5VL_deltafs_is_root_group(H5VL_deltafs_item_t *item)
{
    H5VL_deltafs_group_t *grp;
    hbool_t ret_value = false;

    FUNC_ENTER_NOAPI_NOINIT_NOERR

    if (item->type != H5I_GROUP)
        goto done;

    grp = (H5VL_deltafs_group_t *)item;

    if (grp->index != H5VL_DELTAFS_ROOT_GROUP_INDEX)
        goto done;

    ret_value = true;
done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_is_root_group() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_get_group_index
 *
 * Purpose:     Given a path name and base object, returns the final group 
 *              index
 *
 * Return:      Success:        group index. 
 *              Failure:        error
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_get_group_index(H5VL_deltafs_item_t *item, const char *name,
                            size_t *index, hbool_t is_create)
{
    H5VL_deltafs_file_t *file = item->file;
    long long int gidx = (long long int)-1;
    herr_t ret_value = SUCCEED;
    
    FUNC_ENTER_NOAPI_NOINIT

    HDassert(item);
    HDassert(name);
    HDassert(index);

    if (item->type != H5I_FILE && !H5VL_deltafs_is_root_group(item))
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL,
                "multiple group hierachy not supported")

    // File has a default "/" (Root) group
    if (strncmp(name, "/", 1) == 0) {
        
        if (is_create)
            HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "can't create root group again")
        
        gidx = H5VL_DELTAFS_ROOT_GROUP_INDEX;

    } else {
        if (sscanf(name, H5VL_DELTAFS_H5PART_GROUPNAME_STEP "#%lld", &gidx) != 1)
            HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "unrecognized group name")

        if (gidx < 0)
            HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "invalid group name")

        if (is_create) {
            if ((size_t)gidx != file->fmd.num_groups)
                HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "group numbers should increase monotonically")
            file->fmd.num_groups++;
            file->dirty = true;
        } else {
            if ((size_t)gidx >= file->fmd.num_groups)
                HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "group not found")
        }
    }

    *index = (size_t)gidx;

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_index() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_get_group_name
 *
 * Purpose:     Given group index, returns the group name
 *
 * Return:      Success:        group name. Needs to be freed
 *              Failure:        error
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static char *
H5VL_deltafs_get_group_name(size_t gidx)
{
    char *name;
    char *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /* TODO: Use a slab or reduce size of allocation */
    if(NULL == (name = (char *)H5MM_malloc(HDF5_VOL_DELTAFS_MAX_NAME + 1)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate buffer")

    snprintf(name, HDF5_VOL_DELTAFS_MAX_NAME,
            H5VL_DELTAFS_H5PART_GROUPNAME_STEP "#%lld", (long long int)gidx);
    ret_value = name;

done:
    FUNC_LEAVE_NOAPI(ret_value)
}

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_create_helper
 *
 * Purpose:     Performs the actual group creation.
 *
 * Return:      Success:        group object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static H5VL_deltafs_group_t *
H5VL_deltafs_group_create_helper(H5VL_deltafs_item_t *item, const char *name)
{
    H5VL_deltafs_file_t *file = item->file;
    H5VL_deltafs_group_t *grp = NULL;
    size_t index;
    H5VL_deltafs_group_t *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(file->flags & H5F_ACC_WRONLY);

    /* Allocate a group index */
    if (H5VL_deltafs_get_group_index(item, name, &index, true) < 0)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, NULL, "group index incorrect")

    /* Allocate the group object that is returned to the user */
    if(NULL == (grp = H5FL_CALLOC(H5VL_deltafs_group_t)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate Deltafs group struct")
    
    grp->obj.item.type = H5I_GROUP;
    grp->obj.item.file = file;
    grp->obj.item.rc = 1;
    grp->index = index;
    grp->num_datasets = 0;
    grp->num_elems = 0;
    grp->buf = NULL;
    grp->buf_filled_len = 0;
    grp->buf_size = 0;
    grp->is_read = false;
    grp->dirty = true;

    ret_value = grp;

done:
    /* Cleanup on failure */
    if(NULL == ret_value)
        /* Close group */
        if(grp && H5VL_deltafs_group_close_helper(grp) < 0)
            HDONE_ERROR(H5E_FILE, H5E_CLOSEERROR, NULL, "can't close group")

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_create_helper() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_create
 *
 * Purpose:     Sends a request to Deltafs to create a group
 *
 * Return:      Success:        group object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_group_create(void *_item,
    H5VL_loc_params_t H5_ATTR_UNUSED loc_params, const char *name,
    hid_t gcpl_id, hid_t gapl_id, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    H5VL_deltafs_group_t *grp = NULL;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /* Check for write access */
    if(!(item->file->flags & H5F_ACC_WRONLY))
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "no write intent on file")

    if (gcpl_id != H5P_DEFAULT && gcpl_id != H5P_GROUP_CREATE_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported creation properties")

    if (gapl_id != H5P_DEFAULT && gapl_id != H5P_GROUP_ACCESS_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported access properties")

    if (HDstrlen(name) > HDF5_VOL_DELTAFS_MAX_NAME)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, NULL, "group name too long")

    if (NULL == (grp = H5VL_deltafs_group_create_helper(item, name)))
        HGOTO_ERROR(H5E_SYM, H5E_BADITER, NULL, "can't create group")

    /* Set return value */
    ret_value = (void *)grp;

done:
    /* Cleanup on failure */
    if(NULL == ret_value)
        /* Close group */
        if(grp && H5VL_deltafs_group_close_helper(grp) < 0)
            HDONE_ERROR(H5E_SYM, H5E_CLOSEERROR, NULL, "can't close group")

    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_group_create() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_open_helper
 *
 * Purpose:     Performs the actual group open, given the index
 *
 * Return:      Success:        group object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static H5VL_deltafs_group_t *
H5VL_deltafs_group_open_helper(H5VL_deltafs_file_t *file, size_t index)
{
    H5VL_deltafs_group_t *grp = NULL;
    H5VL_deltafs_group_t *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /* Allocate the group object that is returned to the user */
    if(NULL == (grp = H5FL_CALLOC(H5VL_deltafs_group_t)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate Deltafs group struct")
    
    grp->obj.item.type = H5I_GROUP;
    grp->obj.item.file = file;
    grp->obj.item.rc = 1;
    grp->index = index;

    grp->num_datasets = file->fmd.num_datasets;
    HDassert(grp->num_datasets != 0);

    grp->num_elems = 0;
    grp->buf = NULL;
    grp->buf_filled_len = 0;
    grp->buf_size = 0;
    grp->is_read = false;
    grp->dirty = false;

    ret_value = grp;

done:
    /* Cleanup on failure */
    if(NULL == ret_value)
        /* Close group */
        if(grp && H5VL_deltafs_group_close_helper(grp) < 0)
            HDONE_ERROR(H5E_FILE, H5E_CLOSEERROR, NULL, "can't close group")

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_open_helper() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_open
 *
 * Purpose:     Sends a request to Deltafs to open a group
 *
 * Return:      Success:        dataset object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_group_open(void *_item, H5VL_loc_params_t loc_params,
    const char *name, hid_t H5_ATTR_UNUSED gapl_id, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    H5VL_deltafs_group_t *grp = NULL;
    size_t gidx;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    if (H5VL_OBJECT_BY_ADDR == loc_params.type)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, NULL, "unsupported location parameter")

    //if (gapl_id != H5P_DEFAULT /*|| dxpl_id != H5P_DEFAULT */)
    //    HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported creation/transfer properties")

    /* Open using name parameter */
    if(H5VL_deltafs_get_group_index(item, name, &gidx, false) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_BADVALUE, NULL, "group name invalid")

    if(NULL == (grp = H5VL_deltafs_group_open_helper(item->file, gidx)))
        HGOTO_ERROR(H5E_SYM, H5E_BADITER, NULL, "can't open group")

    /* Set return value */
    ret_value = (void *)grp;

done:
    /* Cleanup on failure */
    if (NULL == ret_value) {

        /* Close group */
        if(grp && H5VL_deltafs_group_close_helper(grp) < 0)
            HDONE_ERROR(H5E_SYM, H5E_CLOSEERROR, NULL, "can't close group")
    } /* end if */

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_open() */



/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_scan
 *
 * Purpose:     Reads in all the values of elements in one file and stores
 *              in buffer of. This is the callback function for deltafs API
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void
H5VL_deltafs_group_scanner(void* _arg, const char H5_ATTR_UNUSED *key,
                        size_t H5_ATTR_UNUSED keylen, const char *value,
                        size_t sz)
{
    H5VL_deltafs_cb_arg_t *arg = (H5VL_deltafs_cb_arg_t *)_arg;
    H5VL_deltafs_group_t *grp = arg->grp;
    char *buf;
    size_t buf_size;
    size_t buf_index;

    FUNC_ENTER_NOAPI_NOINIT_NOERR

    HDassert(grp->buf_filled_len <= grp->buf_size);

    /* TODO: This scanner API should change to allow failures to be returned */
    if (arg->fail == true)
        return;

    if (sz != arg->elem_size) {
        arg->fail = true;
        return;
    }

    /* 
     * TODO: To save data on deltafs, tag can be stored in key and not
     * duplicate in the value
     */

    /* Key is not important as tag is used as key and it is part of value */
    if (grp->buf_size < grp->buf_filled_len + sz) {
   
        /* TODO: Make this O(1) */
        buf_size = grp->buf_size;
        while (buf_size <  grp->buf_filled_len + sz) {
            buf_size += H5VL_DELTAFS_BUF_SIZE_INC;
        }

        if(NULL == (buf = (char *)H5MM_realloc(grp->buf, buf_size))) {
            arg->fail = true;
            return;
        }

        grp->buf = buf;
        grp->buf_size = buf_size;
    }

    buf_index = grp->buf_filled_len;
    memcpy(&grp->buf[buf_index], value, sz);
    grp->buf_filled_len += sz;
    
    grp->num_elems++;

    FUNC_LEAVE_NOAPI_VOID
}


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_read_all
 *
 * Purpose:     Reads in all the values of all dataset of group into buffer
 *
 * Return:      Success:        SUCCESS
 *              Failure:        FAIL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_group_read_all(H5VL_deltafs_group_t *grp)
{
    H5VL_deltafs_file_t *file = grp->obj.item.file;
    deltafs_plfsdir_t *handle = NULL;
    size_t i;
    H5VL_deltafs_cb_arg_t arg;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(grp->is_read == false);
    HDassert(grp->buf == NULL);
    HDassert(grp->buf_size == 0);
    HDassert(grp->num_elems == 0);
    HDassert(!(file->flags & H5F_ACC_WRONLY));

    arg.grp = grp;
    if (H5VL_deltafs_get_elem_size(file, &arg.elem_size, NULL) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't get elem size")

    /*
     * We allocate the maximum buffer size we have seen in past
     * This ensures less calling of realloc
     */
    if (file->max_grp_buf_size != 0) {
        if(NULL == (grp->buf = (char *)H5MM_malloc(file->max_grp_buf_size)))
            HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't allocate space for buffer")
        grp->buf_size = file->max_grp_buf_size;
    }


    /* Scan all rank files for dataset's data */
    for (i = 0; i < file->fmd.total_ranks; i++) {
        
        if ((handle = deltafs_plfsdir_create_handle("", O_RDONLY, 0)) == NULL)
            HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't create deltafs handle")

        if (deltafs_plfsdir_set_rank(handle, (int)(i)) < 0)
            HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't set rank in deltafs handle")
 
        if (deltafs_plfsdir_open(handle, file->name) < 0)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't open file")

        arg.fail = false;
        if (deltafs_plfsdir_scan(handle, (int)grp->index,
                                            H5VL_deltafs_group_scanner,
                                            (void *)&arg) < 0)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't read file")

        if (arg.fail == true)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't read file")

        if (deltafs_plfsdir_free_handle(handle) < 0)
            HDONE_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't free handle")

        handle = NULL;
    }

    grp->is_read = true;
    if (grp->buf_size > file->max_grp_buf_size)
        file->max_grp_buf_size = grp->buf_size;

done:
    if (handle != NULL) {
        if (deltafs_plfsdir_free_handle(handle) < 0)
            HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't free handle")
    }


    if (grp->is_read == false) {
        H5MM_xfree(grp->buf);
        grp->buf_size = 0;
    }
    
    FUNC_LEAVE_NOAPI(ret_value)
}


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_write
 *
 * Purpose:     Writes back values in buffer to the deltafs files
 *
 * Return:      Success:        SUCCESS
 *              Failure:        FAIL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_group_write(H5VL_deltafs_group_t *grp)
{
    H5VL_deltafs_file_t *file = grp->obj.item.file;
    hsize_t elem_size;
    size_t i, j;
    size_t voffset, boffset, keyoff, keysize;
    hsize_t dsets_size[HDF5_VOL_DELTAFS_MAX_DATASET];
    char *value = NULL;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(file->handle != NULL);
    HDassert(grp->dirty == true);
    HDassert(file->flags & H5F_ACC_WRONLY);
    HDassert(grp->num_datasets != 0);
    HDassert(grp->buf != NULL);
    HDassert(grp->num_elems != 0);

    if (file->fmd.num_datasets != grp->num_datasets)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "missing datasets in group")

    if (H5VL_deltafs_get_elem_size(file, &elem_size, dsets_size) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't get elem size")

    HDassert(grp->buf_filled_len == elem_size * grp->num_elems);

    /* TODO: This leads to 3-4 times memcpy throughout the application till deltafs */
    if(NULL == (value = (char *)H5MM_malloc(elem_size)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't allocate space for buffer")

    for (i = 0; i < grp->num_elems; i++) {
        for (j = 0, voffset = 0, boffset = 0; j < grp->num_datasets; j++) {
            size_t len = dsets_size[j];
            size_t boff = boffset + i * len; 
            memcpy(&value[voffset], &grp->buf[boff], len);
            voffset += len;
            boffset += grp->num_elems * len;
        }

        /* Tag is the first dataset */
        keysize = dsets_size[0];
        keyoff = keysize * i;

        if (deltafs_plfsdir_put(file->handle, &grp->buf[keyoff], keysize,
                                (int)grp->index, value, elem_size) < 0)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write to deltafs file")
    }

    if (deltafs_plfsdir_epoch_flush(file->handle, (int)grp->index) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't flush deltafs file")

done:
    H5MM_xfree(value);

    FUNC_LEAVE_NOAPI(ret_value)
}


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_close_helper
 *
 * Purpose:     Closes a deltafs HDF5 group.
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_group_close_helper(H5VL_deltafs_group_t *grp)
{
    H5VL_deltafs_file_t *file = grp->obj.item.file;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(grp);

    if (--grp->obj.item.rc == 0) {

        if (grp->dirty) {
            
            /* When first newly created group is closed, datasets are finalized */
            file->fmd.is_datasets_finalized = true;

            if(H5VL_deltafs_group_write(grp) < 0)
                HDONE_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write to deltafs file")
        }

        H5MM_xfree(grp->buf);
        grp = H5FL_FREE(H5VL_deltafs_group_t, grp);
    }

    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_group_close_helper() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_group_close
 *
 * Purpose:     Closes a deltafs HDF5 group.
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_group_close(void *_grp, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_group_t *grp = (H5VL_deltafs_group_t *)_grp;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(grp);

    if(H5VL_deltafs_group_close_helper(grp) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_BADVALUE, FAIL, "couldn't close group")

done:
    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_group_close() */


#if 0
/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_attribute_create
 *
 * Purpose:     Sends a request to Deltafs to create an attribute
 *
 * Return:      Success:        attribute object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_attribute_create(void H5_ATTR_UNUSED *_item,
    H5VL_loc_params_t H5_ATTR_UNUSED loc_params,
    const char H5_ATTR_UNUSED *name, hid_t H5_ATTR_UNUSED acpl_id,
    hid_t H5_ATTR_UNUSED aapl_id, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT_NOERR

    assert(0);
    ret_value = (void *)1;

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_attribute_create() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_attribute_open
 *
 * Purpose:     Sends a request to Deltafs to open an attribute
 *
 * Return:      Success:        attribute object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_attribute_open(void *_item, H5VL_loc_params_t loc_params,
    const char *name, hid_t H5_ATTR_UNUSED aapl_id, hid_t dxpl_id, void **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT_NOERR

    ret_value = (void *)1;

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_attribute_open() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_attribute_read
 *
 * Purpose:     Reads raw data from an attribute into a buffer.
 *
 * Return:      Success:        0
 *              Failure:        -1, attribute not read.
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_attribute_read(void *_attr, hid_t mem_type_id, void *buf,
    hid_t dxpl_id, void H5_ATTR_UNUSED **req)
{
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT_ERR

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_attribute_read() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_attribute_write
 *
 * Purpose:     Writes raw data from a buffer into an attribute.
 *
 * Return:      Success:        0
 *              Failure:        -1, attribute not written.
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_attribute_write(void *_attr, hid_t mem_type_id, const void *buf,
    hid_t H5_ATTR_UNUSED dxpl_id, void H5_ATTR_UNUSED **req)
{
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT_ERR

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_attribute_write() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_attribute_close
 *
 * Purpose:     Closes a daos-m HDF5 attribute.
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_attribute_close(void *_attr, hid_t dxpl_id, void **req)
{
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT_NOERR

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_attribute_close() */
#endif

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_get_dataset_index
 *
 * Purpose:     Given a name and base object, returns the dataset index and it's
 *              group index
 *
 * Return:      Success:        dataset and parent group index. 
 *              Failure:        error
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_get_dataset_index(H5VL_deltafs_item_t *item, const char *name,
                            hid_t type_id, size_t *index_out,
                            hbool_t create_new)
{
    H5VL_deltafs_file_t *file = item->file;
    H5VL_deltafs_group_t *grp;
    size_t i;
    H5VL_deltafs_dmd_t *dmd;
    size_t didx = (size_t)-1;
    herr_t ret_value = SUCCEED;
    
    FUNC_ENTER_NOAPI_NOINIT

    HDassert(item);
    HDassert(name);
    HDassert(index_out);

    /* TODO: Support opening of dataset given full path */
    if (item->type != H5I_GROUP)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL,
                "multiple group hierachy not supported")

    grp = (H5VL_deltafs_group_t *)item;

    if (HDstrlen(name) > HDF5_VOL_DELTAFS_MAX_NAME)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "group name too long")

    /* TODO: Can use name to get index e.g Step#1 */
    for (i = 0; i < file->fmd.num_datasets; i++) {
        if (HDstrcmp(file->fmd.dmd[i].name, name) == 0) {
            didx = i;
            break;
        }
    }
        
    if (create_new == false) {
        if (didx == (size_t)-1 || didx >= grp->num_datasets)
            HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "dataset not found")
    } else if (create_new == true) {
        if (didx != (size_t)-1 && didx < grp->num_datasets) {
            HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "dataset already exists")
        } else if (didx != (size_t)-1 && didx != grp->num_datasets) {
            HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "invalid dataset tried to be created")
        } else if (didx == (size_t)-1 &&
                file->fmd.is_datasets_finalized == true) {
            HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "invalid dataset tried to be created")
        } else {

            didx = grp->num_datasets;
            dmd = &file->fmd.dmd[didx];

            /* 
             * If new dataset created in file, store type
             * else compare to make sure it is same
             */
            if (dmd->is_initialized == false) {

                if((dmd->type_id = H5Tcopy(type_id)) < 0)
                    HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't get datatype ID of dataset")

                /* 
                 * Write dataset type 
                 * We decode here instead of decoding at the end from type id 
                 * because when library is being terminated, due to sequence of termination
                 * it is possible for H5T module to be terminated before H5VL is 
                 * terminated. Hence at that instande H5Tencode() might not work
                 */
                if(H5Tencode(dmd->type_id, NULL, &dmd->type_buf_size) < 0)
                    HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, FAIL, "can't determine serialized length of datatype")
        
                if(NULL == (dmd->type_buf = (char *)H5MM_malloc(dmd->type_buf_size)))
                    HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, FAIL, "can't allocate buffer for serialized datatype")

                if(H5Tencode(dmd->type_id, dmd->type_buf, &dmd->type_buf_size) < 0)
                    HGOTO_ERROR(H5E_DATASET, H5E_CANTENCODE, FAIL, "can't serialize datatype")

                strncpy(dmd->name, name, HDF5_VOL_DELTAFS_MAX_NAME + 1);

                dmd->is_initialized = true;
                
                file->fmd.num_datasets++;
            } else {
                if (H5Tequal(dmd->type_id, type_id) != TRUE)
                    HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "type size doesn't match")
            }

            didx = grp->num_datasets++;
            file->dirty = true;
        }   
    }

    *index_out = didx;

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_dataset_index() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_dataset_create
 *
 * Purpose:     Sends a request to Deltafs to create a dataset
 *
 * Return:      Success:        dataset object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              November, 2016
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_dataset_create(void *_item,
    H5VL_loc_params_t H5_ATTR_UNUSED loc_params, const char *name,
    hid_t dcpl_id, hid_t dapl_id, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    H5VL_deltafs_file_t *file = item->file;
    H5VL_deltafs_group_t *grp =  (H5VL_deltafs_group_t *)item;
    H5VL_deltafs_dset_t *dset = NULL;
    H5P_genplist_t *plist = NULL;      /* Property list pointer */
    hid_t type_id;
    size_t didx;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

     
    /* Check for write access */
    if(!(file->flags & H5F_ACC_WRONLY))
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "no write intent on file")

    if (item->type != H5I_GROUP)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "can only create dataset under a group")

    if (dapl_id != H5P_DEFAULT && dapl_id != H5P_DATASET_ACCESS_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported access properties")

    /* Get the dcpl plist structure */
    if(NULL == (plist = (H5P_genplist_t *)H5I_object(dcpl_id)))
        HGOTO_ERROR(H5E_ATOM, H5E_BADATOM, NULL, "can't find object for ID")

    /* get creation properties */
    if(H5P_get(plist, H5VL_PROP_DSET_TYPE_ID, &type_id) < 0)
        HGOTO_ERROR(H5E_PLIST, H5E_CANTGET, NULL, "can't get property value for datatype id")

    if (H5VL_deltafs_get_dataset_index(item, name, type_id, &didx, true) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "couldn't create dataset")
 
    /* Allocate the dataset object that is returned to the user */
    if(NULL == (dset = H5FL_CALLOC(H5VL_deltafs_dset_t)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate Deltafs dataset struct")

    dset->obj.item.type = H5I_DATASET;
    dset->obj.item.file = item->file;
    dset->obj.item.rc = 1;
    dset->index = didx;
    dset->dmd = &file->fmd.dmd[didx];
    dset->parent_grp = grp;
    grp->obj.item.rc++;

    /* Set return value */
    ret_value = (void *)dset;

done:
    /* Cleanup on failure */
    if(NULL == ret_value)
        /* Close dataset */
        if(dset && H5VL_deltafs_dataset_close_helper(dset) < 0)
            HDONE_ERROR(H5E_DATASET, H5E_CLOSEERROR, NULL, "can't close dataset")
    
    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_dataset_create() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_dataset_open
 *
 * Purpose:     Sends a request to Deltafs to open a dataset
 *
 * Return:      Success:        dataset object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_dataset_open(void *_item,
    H5VL_loc_params_t loc_params, const char *name,
    hid_t H5_ATTR_UNUSED dapl_id, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    H5VL_deltafs_file_t *file = item->file;
    H5VL_deltafs_group_t *grp =  (H5VL_deltafs_group_t *)item;
    H5VL_deltafs_dmd_t *dmd = NULL;
    H5VL_deltafs_dset_t *dset = NULL;
    size_t didx;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    if (item->type != H5I_GROUP)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "can only create dataset under a group")

    if (H5VL_OBJECT_BY_ADDR == loc_params.type)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, NULL, "unsupported location parameter")

    //if (dapl_id != H5P_DEFAULT /*|| dxpl_id != H5P_DEFAULT*/)
    //    HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported access/transfer properties")

    if (H5VL_deltafs_get_dataset_index(item, name, 0, &didx, false) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "dataset name invalid")

    dmd = &file->fmd.dmd[didx];
    
    /* Allocate the dataset object that is returned to the user */
    if(NULL == (dset = H5FL_CALLOC(H5VL_deltafs_dset_t)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate Deltafs dataset struct")
    dset->obj.item.type = H5I_DATASET;
    dset->obj.item.file = item->file;
    dset->obj.item.rc = 1;
    dset->index = didx;
    dset->dmd = dmd;
    dset->parent_grp = grp;
    grp->obj.item.rc++;

    /* TODO: Retrieve stored values */
    ret_value = (void *)dset;

done:
    /* Cleanup on failure */
    if(NULL == ret_value) {
        /* Close dataset */
        if(dset && H5VL_deltafs_dataset_close_helper(dset) < 0)
            HDONE_ERROR(H5E_DATASET, H5E_CLOSEERROR, NULL, "can't close dataset")
    } /* end if */

    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_dataset_open() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_xfer
 *
 * Purpose:     Given a source and setination dataspace with a selection and 
 *              the datatype (element) size, transfer bytes from src to destination
 *              Does not releae buffers on error.
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_xfer(void *_dest_buf, H5S_t *dest_space, size_t dest_type_size,
        const void *_src_buf, H5S_t *src_space, size_t src_type_size, size_t total_size)
{
    uint8_t *dest_buf = (uint8_t *)_dest_buf;
    const uint8_t *src_buf = (const uint8_t *)_src_buf;
    H5S_sel_iter_t src_sel_iter;                /* Selection iteration info */
    hbool_t src_sel_iter_init = FALSE;      /* Selection iteration info has been initialized */
    H5S_sel_iter_t dest_sel_iter;
    hbool_t dest_sel_iter_init = FALSE;
    size_t src_nseq = 0, dest_nseq = 0;
    size_t src_i = 0, dest_i = 0;
    size_t src_nelem, dest_nelem;
    hsize_t src_off[H5VL_DELTAFS_SEQ_LIST_LEN];
    size_t src_len[H5VL_DELTAFS_SEQ_LIST_LEN];
    hsize_t dest_off[H5VL_DELTAFS_SEQ_LIST_LEN];
    size_t dest_len[H5VL_DELTAFS_SEQ_LIST_LEN];
    size_t total_xfer = 0;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(src_buf && dest_buf);
    HDassert(src_space && dest_space);

    if(H5S_select_iter_init(&src_sel_iter, src_space, src_type_size) < 0)
        HGOTO_ERROR(H5E_DATASPACE, H5E_CANTINIT, FAIL, "unable to initialize selection iterator")
    src_sel_iter_init = TRUE;

     if(H5S_select_iter_init(&dest_sel_iter, dest_space, dest_type_size) < 0)
        HGOTO_ERROR(H5E_DATASPACE, H5E_CANTINIT, FAIL, "unable to initialize selection iterator")
    dest_sel_iter_init = TRUE;

    /* Generate sequences from the file space until finished */
    do {
        /* Get the sequences of bytes */
        if(src_i == src_nseq) {
                src_i = 0; 
                if (H5S_SELECT_GET_SEQ_LIST(src_space, 0, &src_sel_iter,
                    (size_t)H5VL_DELTAFS_SEQ_LIST_LEN, (size_t)-1, &src_nseq, &src_nelem, src_off, src_len) < 0)
                    HGOTO_ERROR(H5E_DATASPACE, H5E_CANTGET, FAIL, "sequence length generation failed")
        }
        if(dest_i == dest_nseq) {
            dest_i = 0;
            if (H5S_SELECT_GET_SEQ_LIST(dest_space, 0, &dest_sel_iter,
                    (size_t)H5VL_DELTAFS_SEQ_LIST_LEN, (size_t)-1, &dest_nseq, &dest_nelem, dest_off, dest_len) < 0)
                HGOTO_ERROR(H5E_DATASPACE, H5E_CANTGET, FAIL, "sequence length generation failed")
        }

        /* Copy wrt to offsets/lengths */
        while (src_i < src_nseq && dest_i < dest_nseq) {
            size_t xfer_len;
            hsize_t src_offset = src_off[src_i];
            hsize_t dest_offset = dest_off[dest_i];

            if (src_len[src_i] < dest_len[dest_i]) {
                xfer_len = src_len[src_i];
                src_i++;
                dest_len[dest_i] -= xfer_len;
                dest_off[dest_i] += xfer_len;
            } else if (src_len[src_i] > dest_len[dest_i]) {
                xfer_len = dest_len[src_i];
                dest_i++;
                src_len[src_i] -= xfer_len;
                src_off[src_i] += xfer_len;
            } else {
                xfer_len = src_len[src_i];
                src_i++;
                dest_i++;
            }

            HDmemcpy((void *)&dest_buf[dest_offset], (const void *)&src_buf[src_offset], xfer_len);
            total_xfer += xfer_len;
        }

    } while(src_nseq == H5VL_DELTAFS_SEQ_LIST_LEN || dest_nseq == H5VL_DELTAFS_SEQ_LIST_LEN);

    /* XXX: Is this always true? */
    HDassert(total_xfer == total_size);

done:
    /* Release selection iterators */
    if(src_sel_iter_init && H5S_SELECT_ITER_RELEASE(&src_sel_iter) < 0)
        HDONE_ERROR(H5E_DATASPACE, H5E_CANTRELEASE, FAIL, "unable to release selection iterator")
    if(dest_sel_iter_init && H5S_SELECT_ITER_RELEASE(&dest_sel_iter) < 0)
        HDONE_ERROR(H5E_DATASPACE, H5E_CANTRELEASE, FAIL, "unable to release selection iterator")

    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_xfer() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_dataset_read
 *
 * Purpose:     Reads raw data from a dataset into a buffer.
 *`
 * Return:      Success:        0
 *              Failure:        -1, dataset not read.
 *
 * Programmer:  Saksham Jain
 *              November, 2016
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_dataset_read(void *_dset, hid_t mem_type_id, hid_t mem_space_id,
    hid_t H5_ATTR_UNUSED file_space_id, hid_t H5_ATTR_UNUSED dxpl_id, void *buf,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_dset_t *dset = (H5VL_deltafs_dset_t *)_dset;
    H5VL_deltafs_group_t *grp = dset->parent_grp;
    H5VL_deltafs_file_t *file = dset->obj.item.file;
    H5VL_deltafs_dmd_t *dmd = dset->dmd;
    hid_t real_file_space_id = -1;
    hid_t real_mem_space_id = -1;
    H5S_t *file_space = NULL;
    H5S_t *mem_space = NULL;
    hsize_t type_size;
    size_t i;
    hsize_t len, offset, elem_size, num_elems;
    hsize_t dsets_size[HDF5_VOL_DELTAFS_MAX_DATASET];
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    if (file->flags & H5F_ACC_WRONLY)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "no read intent on file")

    /*
     * TODO: We don't support conversion currently. Type size should be same
     * of memory and that in the file
     */
    HDassert(dmd->is_initialized);

    if (H5Tequal(mem_type_id, dmd->type_id) != true)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "improper mem type")

    if ((type_size = H5Tget_size(mem_type_id)) == 0)
        HGOTO_ERROR(H5E_DATATYPE, H5E_CANTGET, FAIL, "can't get source type size")

    if (H5VL_deltafs_get_elem_size(file, &elem_size, dsets_size) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't get elem size")

    HDassert(grp->num_elems != 0);
    num_elems = grp->num_elems;
    len = grp->num_elems * elem_size;

    if((real_file_space_id = H5Screate_simple (1, &len, NULL)) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't create dataspace")

    if(mem_space_id == H5S_ALL) {
        if((real_mem_space_id = H5Screate_simple(1, &num_elems, NULL)) < 0)
            HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't create dataspace")
    } else {
        real_mem_space_id = mem_space_id;
    }

    for (i = 0, offset = 0; i < dset->index; i++)
        offset += dsets_size[i];

    if (H5Sselect_hyperslab(real_file_space_id, H5S_SELECT_SET, &offset,
			                    &elem_size, &num_elems, &dsets_size[dset->index]) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't select dataspace")

    /* Get file dataspace object */
    if(NULL == (file_space = (H5S_t *)H5I_object(real_file_space_id)))
            HGOTO_ERROR(H5E_ATOM, H5E_BADATOM, FAIL, "can't find object for ID")

    if(NULL == (mem_space = (H5S_t *)H5I_object(real_mem_space_id)))
            HGOTO_ERROR(H5E_ATOM, H5E_BADATOM, FAIL, "can't find object for ID")

    if (grp->is_read == false && H5VL_deltafs_group_read_all(grp) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't read group data")

    /* Transfer from dset buf to buffer */
    if(H5VL_deltafs_xfer((void *)buf, mem_space, type_size,
                (void *)grp->buf, file_space, 1, num_elems * type_size) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTINIT, FAIL, "can't read from memory")

done:
    if (real_file_space_id > 0 && H5Sclose(real_file_space_id ) < 0)
        HDONE_ERROR(H5E_DATASET, H5E_CANTINIT, FAIL, "can't close dataspace")

    if (mem_space_id == H5S_ALL && real_mem_space_id > 0 && H5Sclose(real_mem_space_id) < 0)
        HDONE_ERROR(H5E_DATASET, H5E_CANTINIT, FAIL, "can't close dataspace")

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_dataset_read() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_dataset_write
 *
 * Purpose:     Writes raw data from a buffer into a dataset.
 *
 * Return:      Success:        0
 *              Failure:        -1, dataset not written.
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_dataset_write(void *_dset, hid_t mem_type_id, hid_t mem_space_id,
    hid_t H5_ATTR_UNUSED file_space_id, hid_t H5_ATTR_UNUSED dxpl_id,
    const void *buf, void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_dset_t *dset = (H5VL_deltafs_dset_t *)_dset;
    H5VL_deltafs_group_t *grp = dset->parent_grp;
    H5VL_deltafs_file_t *file = dset->obj.item.file;
    H5VL_deltafs_dmd_t *dmd = dset->dmd;
    hid_t real_file_space_id = -1;
    hid_t real_mem_space_id;
    H5S_t *file_space = NULL;
    H5S_t *mem_space = NULL;
    size_t type_size;
    hsize_t nelems;
    hssize_t tnelems;
    size_t len, buf_size;
    char *gbuf;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    /* Check for write access */
    if(!(file->flags & H5F_ACC_WRONLY))
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "no write intent on file")

    /*
     * TODO: We don't support conversion currently. Type size should be same
     * of memory and that in the file
     */
    HDassert(dmd->is_initialized);

    if (H5Tequal(mem_type_id, dmd->type_id) != true)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "improper mem type")

    if((type_size = H5Tget_size(mem_type_id)) == 0)
        HGOTO_ERROR(H5E_DATATYPE, H5E_CANTGET, FAIL, "can't get source type size")

    /* Get total elements */
    if((tnelems = H5Sget_select_npoints(mem_space_id)) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't get number of elements in selection")
    
    nelems = (hsize_t)tnelems;
    len = nelems * type_size;

    if (grp->num_elems == 0) {
        grp->num_elems = nelems;
    } else if (grp->num_elems != nelems) {
         HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "incorrect number of elements")
    }

    /* Expand group if it is not sufficiently large */
    if (grp->buf_size - grp->buf_filled_len < len) {
        buf_size = grp->buf_filled_len + len;
        if(NULL == (gbuf = (char *)H5MM_realloc(grp->buf, buf_size)))
            HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, FAIL, "can't allocate buffer for serialized datatype")

        grp->buf = gbuf;
        grp->buf_size = buf_size;

        if (buf_size > file->max_grp_buf_size)
            file->max_grp_buf_size = buf_size;
    }

    if((real_file_space_id = H5Screate_simple (1, &nelems, NULL)) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't create dataspace");

    if(mem_space_id == H5S_ALL)
        real_mem_space_id = real_file_space_id;
    else
        real_mem_space_id = mem_space_id;

     /* Get file dataspace object */
    if(NULL == (file_space = (H5S_t *)H5I_object(real_file_space_id)))
            HGOTO_ERROR(H5E_ATOM, H5E_BADATOM, FAIL, "can't find object for ID");

    if(NULL == (mem_space = (H5S_t *)H5I_object(real_mem_space_id)))
            HGOTO_ERROR(H5E_ATOM, H5E_BADATOM, FAIL, "can't find object for ID");

    /* Transfer from buf to dset buffer */
    if(H5VL_deltafs_xfer((void *)&grp->buf[grp->buf_filled_len],
                file_space, type_size, (const void *)buf, mem_space, type_size, len) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTINIT, FAIL, "can't read from memory")

    grp->buf_filled_len += len;
    grp->dirty = true;

done:

    if (real_file_space_id > 0 && H5Sclose(real_file_space_id ) < 0)
        HDONE_ERROR(H5E_DATASET, H5E_CANTINIT, FAIL, "can't close dataspace")

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_dataset_write() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_dataset_get
 *
 * Purpose:     Gets certain information about a dataset
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              March, 2017
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_dataset_get(void *_dset, H5VL_dataset_get_t get_type, 
    hid_t H5_ATTR_UNUSED dxpl_id, void H5_ATTR_UNUSED **req, va_list arguments)
{
    H5VL_deltafs_dset_t *dset = (H5VL_deltafs_dset_t *)_dset;
    H5VL_deltafs_file_t *file = dset->obj.item.file;
    hsize_t num_elems;
    herr_t ret_value = SUCCEED;    /* Return value */

    FUNC_ENTER_NOAPI_NOINIT

    switch (get_type) {
        case H5VL_DATASET_GET_SPACE:
            {
                hid_t *ret_id = va_arg(arguments, hid_t *);
                H5VL_deltafs_group_t *grp = dset->parent_grp;

                if (grp->is_read == false && H5VL_deltafs_group_read_all(grp) < 0)
                    HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't read group data")

                /* We only support query for dataspace when reading */
                if ((file->flags & H5F_ACC_WRONLY) != 0)
                    HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't get dataspace when file open for write");

                num_elems = grp->num_elems;
                if((*ret_id = H5Screate_simple (1, &num_elems, NULL)) < 0)
                    HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't get dataspace ID of dataset");
                break;
            } /* end block */
        case H5VL_DATASET_GET_SPACE_STATUS:
            {
                H5D_space_status_t *allocation = va_arg(arguments, H5D_space_status_t *);

                /* Retrieve the dataset's space status */
                *allocation = H5D_SPACE_STATUS_NOT_ALLOCATED;
                break;
            } /* end block */
        case H5VL_DATASET_GET_TYPE:
            {
                hid_t *ret_id = va_arg(arguments, hid_t *);

                /* Retrieve the dataset's datatype */
                if((*ret_id = H5Tcopy(dset->dmd->type_id)) < 0)
                    HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, FAIL, "can't get datatype ID of dataset")
                break;
            } /* end block */
        case H5VL_DATASET_GET_DCPL:
        case H5VL_DATASET_GET_DAPL:
        case H5VL_DATASET_GET_STORAGE_SIZE:
        case H5VL_DATASET_GET_OFFSET:
        default:
            HGOTO_ERROR(H5E_VOL, H5E_UNSUPPORTED, FAIL, "can't get this type of information from dataset")
    } /* end switch */

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_daosm_dataset_get() */

/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_dataset_close_helper
 *
 * Purpose:     Closes a deltafs HDF5 dataset.
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              November, 2016
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_dataset_close_helper(H5VL_deltafs_dset_t *dset)
{
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(dset);

    if (--dset->obj.item.rc == 0) {

        /* Let go of the reference count taken fro the group */
        if(dset->parent_grp && H5VL_deltafs_group_close_helper(dset->parent_grp) < 0)
            HDONE_ERROR(H5E_FILE, H5E_CLOSEERROR, FAIL, "can't close group")

        dset = H5FL_FREE(H5VL_deltafs_dset_t, dset);
    }

    FUNC_LEAVE_NOAPI(ret_value)
}


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_dataset_close
 *
 * Purpose:     Closes a daos-m HDF5 dataset.
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              November, 2016
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_dataset_close(void *_dset, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_dset_t *dset = (H5VL_deltafs_dset_t *)_dset;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT_NOERR

    HDassert(dset);

    ret_value = H5VL_deltafs_dataset_close_helper(dset);

    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_dataset_close() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_link_specific
 *
 * Purpose:     Specific operations with links
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_link_specific(void *_item, H5VL_loc_params_t loc_params,
    H5VL_link_specific_t specific_type, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req, va_list arguments)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    H5VL_deltafs_file_t *file = item->file;
    void *target_obj = item;
    hid_t target_obj_id = -1;
    herr_t ret_value = SUCCEED;    /* Return value */

    FUNC_ENTER_NOAPI_NOINIT

    switch (specific_type) {
        /* H5Lexists */
        case H5VL_LINK_EXISTS:
            {
                htri_t *lexists_ret = va_arg(arguments, htri_t *);
		        size_t gidx, didx;

                HDassert(H5VL_OBJECT_BY_NAME == loc_params.type);

    		/* 
	    	 * If item is file, links can be only groups.
		     * If item is groups, links can be only datasets
    		 */
    		if (item->type == H5I_FILE || H5VL_deltafs_is_root_group(item)) {
	    		if(H5VL_deltafs_get_group_index(item, loc_params.loc_data.loc_by_name.name, &gidx, false) < 0)
          			HGOTO_ERROR(H5E_SYM, H5E_BADVALUE, FAIL, "group name invalid")
    		} else if (item->type == H5I_GROUP) {
	    		 if (H5VL_deltafs_get_dataset_index(item, loc_params.loc_data.loc_by_name.name, 
                                                    0, &didx, false) < 0)
        			HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "dataset name invalid")
    		} else {
	    		HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "invalid item")
		    }

                *lexists_ret = 1;

                break;
            } /* end block */

        case H5VL_LINK_ITER:
            {
                hbool_t recursive = va_arg(arguments, int);
                H5_index_t H5_ATTR_UNUSED idx_type = (H5_index_t)va_arg(arguments, int);
                H5_iter_order_t order = (H5_iter_order_t)va_arg(arguments, int);
                hsize_t *idx = va_arg(arguments, hsize_t *);
                H5L_iterate_t op = va_arg(arguments, H5L_iterate_t);
                void *op_data = va_arg(arguments, void *);
                H5L_info_t linfo;
                herr_t op_ret;
                char *p;
		        ssize_t i;
                size_t num_links;
		        H5VL_deltafs_group_t *grp = NULL;
		        hbool_t isFile;
                hbool_t inc;

                /* Determine the target group */
                if(loc_params.type == H5VL_OBJECT_BY_SELF) {
                    /* Use item as attribute parent object, or the root group if item is a
                     * file */
                    
                    if (item->type == H5I_FILE || H5VL_deltafs_is_root_group(item)) {
	    			    num_links = file->fmd.num_groups;
		    		    isFile = true; 
                    } else if(item->type == H5I_GROUP) {
	    			    grp = (H5VL_deltafs_group_t *)item;
		    		    num_links = grp->num_datasets;
			    	    isFile = false;
    	            } else {
                        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, FAIL, "item not a file or group")
			        }	
                } /* end if */
        		else {
                    HGOTO_ERROR(H5E_VOL, H5E_UNSUPPORTED, FAIL, "unsupported location params")
        		} /* end else */

                /* Iteration restart not supported */
                if(idx && (*idx != 0))
                    HGOTO_ERROR(H5E_SYM, H5E_UNSUPPORTED, FAIL, "iteration restart not supported (must start from 0)")

                /* Ordered iteration not supported */
                if(order != H5_ITER_INC && order != H5_ITER_DEC && order != H5_ITER_NATIVE)
                    HGOTO_ERROR(H5E_SYM, H5E_UNSUPPORTED, FAIL, "ordered iteration not supported")

                /* Recursive iteration not supported */
                if(recursive)
                    HGOTO_ERROR(H5E_SYM, H5E_UNSUPPORTED, FAIL, "recusive iteration not supported")

                /* Initialize const linfo info */
                linfo.corder_valid = FALSE;
                linfo.corder = 0;
                linfo.cset = H5T_CSET_ASCII;
		        linfo.type = H5L_TYPE_HARD;
		        /* TODO: linfo.u.address needs to be populated with address */

                /* Register id for target_grp */
                if((target_obj_id = H5VL_object_register(target_obj, item->type, H5VL_DELTAFS_g, TRUE)) < 0)
                    HGOTO_ERROR(H5E_ATOM, H5E_CANTREGISTER, FAIL, "unable to atomize object handle")
                ((H5VL_deltafs_item_t *)target_obj)->rc++;

                /* Loop to retrieve groups/datasets and make callbacks */
        		op_ret = 0;
                inc = order == H5_ITER_DEC ? false : true;
        		for((inc == true) ? (i = 0) : (i = (ssize_t)num_links - 1);
                        (inc == true) ? (i < (ssize_t)num_links) : (i >= 0);
                        (inc == true) ? i++: i--) {
		        
    		        if (isFile) {
        	    		p =  H5VL_deltafs_get_group_name((size_t)i);
    	    	    } else {
	    	            p = file->fmd.dmd[i].name;
		            }
		    
		            /* Make callback */
		            if((op_ret = op(target_obj_id, p, &linfo, op_data)) < 0)
		                HGOTO_ERROR(H5E_SYM, H5E_BADITER, op_ret, "operator function returned failure")

                    if (isFile)
                        H5MM_xfree(p);

        		    /* Advance idx */
	        	    if(idx)
		                (*idx)++;

        		    if (op_ret != 0)
           		        break;

    		    } /* end if */

                /* Set return value */
                ret_value = op_ret;

                break;
            } /* end block */
        case H5VL_LINK_DELETE:
            HGOTO_ERROR(H5E_VOL, H5E_UNSUPPORTED, FAIL, "unsupported specific operation")
        default:
            HGOTO_ERROR(H5E_VOL, H5E_BADVALUE, FAIL, "invalid specific operation")
    } /* end switch */

done:
    if(target_obj_id >= 0) {
        if(H5I_dec_app_ref(target_obj_id) < 0)
            HDONE_ERROR(H5E_SYM, H5E_CLOSEERROR, FAIL, "can't close group id")
        target_obj_id = -1;
    } /* end if */

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_link_specific() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_object_open
 *
 * Purpose:     Opens a Deltafs HDF5 object.
 *
 * Return:      Success:        object. 
 *              Failure:        NULL
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_object_open(void *_item, H5VL_loc_params_t loc_params, 
    H5I_type_t *opened_type, hid_t dxpl_id, void **req)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    void *obj = NULL;
    H5I_type_t obj_type;
    H5VL_loc_params_t sub_loc_params;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /* Check loc_params type */
    if (H5VL_OBJECT_BY_NAME != loc_params.type)
        HGOTO_ERROR(H5E_VOL, H5E_UNSUPPORTED, NULL, "unsupported location params")

    /* File has only groups as members, groups have only datasets */
    if(item->type == H5I_FILE || H5VL_deltafs_is_root_group(item)) {
        obj_type = H5I_GROUP;
    } else if (item->type == H5I_GROUP) {
        obj_type = H5I_DATASET;
	} else {
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "item not a file or group")
	}

        /* Set up sub_loc_params */
    sub_loc_params.obj_type = item->type;
    sub_loc_params.type = H5VL_OBJECT_BY_NAME;

    /* Call type's open function */
    if(obj_type == H5I_GROUP) {
        if(NULL == (obj = H5VL_deltafs_group_open(item, sub_loc_params,
                        loc_params.loc_data.loc_by_name.name,
                        H5P_GROUP_ACCESS_DEFAULT, dxpl_id, req)))
            HGOTO_ERROR(H5E_OHDR, H5E_CANTOPENOBJ, NULL, "can't open group")
    } /* end if */
    else if(obj_type == H5I_DATASET) {
        if(NULL == (obj = H5VL_deltafs_dataset_open(item, sub_loc_params,
                        loc_params.loc_data.loc_by_name.name,
                        H5P_DATASET_ACCESS_DEFAULT, dxpl_id, req)))
            HGOTO_ERROR(H5E_OHDR, H5E_CANTOPENOBJ, NULL, "can't open dataset")
    } /* end if */
    
    /* Set return value */
    if(opened_type)
        *opened_type = obj_type;
    ret_value = obj;

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_object_open() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_object_optional
 *
 * Purpose:     Optional operations with objects
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_object_optional(void *_item, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req, va_list arguments)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    H5VL_deltafs_obj_t *target_obj = NULL;
    H5VL_object_optional_t optional_type = (H5VL_object_optional_t)va_arg(arguments, int);
    H5VL_loc_params_t loc_params = va_arg(arguments, H5VL_loc_params_t);
    herr_t ret_value = SUCCEED;    /* Return value */

    FUNC_ENTER_NOAPI_NOINIT

    /* Determine target object */
    if(item->type != H5I_FILE && item->type != H5I_GROUP && item->type != H5I_DATASET)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, FAIL, "item not a file/group/dataset")

    /* Determine target object */
    if(loc_params.type == H5VL_OBJECT_BY_SELF) {
        /* Use item as attribute parent object, or the root group if item is a
         * file */
        target_obj = (H5VL_deltafs_obj_t *)item;
        target_obj->item.rc++;
    } /* end if */
    else if(loc_params.type == H5VL_OBJECT_BY_NAME) {
        /* Open target_obj */
        if(NULL == (target_obj = (H5VL_deltafs_obj_t *)H5VL_deltafs_object_open(item, loc_params, NULL, dxpl_id, req)))
            HGOTO_ERROR(H5E_OHDR, H5E_CANTOPENOBJ, FAIL, "can't open object")
    } /* end else */
    else
        HGOTO_ERROR(H5E_OHDR, H5E_UNSUPPORTED, FAIL, "unsupported object operation location parameters type")

    switch (optional_type) {
        /* H5Oget_info / H5Oget_info_by_name / H5Oget_info_by_idx */
        case H5VL_OBJECT_GET_INFO:
            {
                H5O_info_t  *obj_info = va_arg(arguments, H5O_info_t *);

                /* Initialize obj_info - most fields are not valid and will
                 * simply be set to 0 */
                HDmemset(obj_info, 0, sizeof(*obj_info));

                if(target_obj->item.type == H5I_GROUP)
                    obj_info->type = H5O_TYPE_GROUP;
                else if(target_obj->item.type == H5I_DATASET)
                    obj_info->type = H5O_TYPE_DATASET;
                else
                    HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, FAIL, "invalid item")
                break;
            } /* end block */
                
        case H5VL_OBJECT_GET_COMMENT:
        case H5VL_OBJECT_SET_COMMENT:
            HGOTO_ERROR(H5E_VOL, H5E_UNSUPPORTED, FAIL, "unsupported optional operation")
        default:
            HGOTO_ERROR(H5E_VOL, H5E_BADVALUE, FAIL, "invalid optional operation")
    } /* end switch */

done:
    if(target_obj) {
        if(H5VL_deltafs_object_close(target_obj, dxpl_id, req) < 0)
            HDONE_ERROR(H5E_OHDR, H5E_CLOSEERROR, FAIL, "can't close object")
        target_obj = NULL;
    } /* end else */


    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_object_optional() */


/*-------------------------------------------------------------------------
 * Function:    H5VL_deltafs_object_close
 *
 * Purpose:     Closes a deltafs HDF5 object.
 *
 * Return:      Success:        0
 *              Failure:        -1
 *
 * Programmer:  Saksham Jain
 *              March, 2018
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_object_close(void *_obj, hid_t dxpl_id, void **req)
{
    H5VL_deltafs_obj_t *obj = (H5VL_deltafs_obj_t *)_obj;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(obj);
    HDassert(obj->item.type == H5I_GROUP || obj->item.type == H5I_DATASET);

    /* Call type's close function */
    if(obj->item.type == H5I_GROUP) {
        if(H5VL_deltafs_group_close(obj, dxpl_id, req))
            HGOTO_ERROR(H5E_SYM, H5E_CLOSEERROR, FAIL, "can't close group")
    } /* end if */
    else if(obj->item.type == H5I_DATASET) {
        if(H5VL_deltafs_dataset_close(obj, dxpl_id, req))
            HGOTO_ERROR(H5E_DATASET, H5E_CLOSEERROR, FAIL, "can't close dataset")
    } /* end if */
    else
        HDassert(0 && "Invalid object type");

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_object_close() */

