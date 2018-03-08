/*
 * Programmer:  Saksham Jain <sakshamj@andrew.cmu.edu>
 *              March, 2018
 *
 * Purpose: The Deltafs VOL plugin where access is forwarded to the Deltafs
 * library 
 */

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

#include "deltafs_api.h"

#define H5VL_DELTAFS_ENABLE_ENV "HDF5_DELTAFS_ENABLE"

/* VOL plugin value */
hid_t H5VL_DELTAFS_g = -1;

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

/* The Deltafs VOL plugin struct */
static H5VL_class_t H5VL_deltafs_g = {
    HDF5_VOL_DELTAFS_VERSION_1,                 /* Version number */
    H5_VOL_DELTAFS,                             /* Plugin value */
    "deltafs_vol",                              /* name */
    NULL,                                       /* initialize */
    NULL,                                       /* terminate */
    0,                                          /*fapl_size */
    NULL,                                       /*fapl_copy */
    NULL,                                       /*fapl_free */

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

    {                                           /* dataset_cls */
        H5VL_deltafs_dataset_create,            /* create */
        H5VL_deltafs_dataset_open,              /* open */
        H5VL_deltafs_dataset_read,              /* read */
        H5VL_deltafs_dataset_write,             /* write */
        NULL,                                   /* get */
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
        NULL,                                   /* specific */
        NULL                                    /* optional */
    },

    {                                           /* object_cls */
        NULL,                                   /* open */
        NULL,                                   /* copy */
        NULL,                                   /* get */
        NULL,                                   /* specific */
        NULL                                    /* optional */
    },
    {
        NULL,
        NULL,
        NULL,
    },
    NULL
};

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

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_init() */


/*-------------------------------------------------------------------------
 * Function:    H5VLdeltafs_is_enabled
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

    hbool_t ret_value = TRUE;

 //   FUNC_ENTER_NOAPI_NOERR

    ret_value = (NULL != HDgetenv(H5VL_DELTAFS_ENABLE_ENV));

//    FUNC_LEAVE_NOAPI(ret_value)
    return ret_value;
}

/*-------------------------------------------------------------------------
 * Function:    H5VLdeltafs_set_plugin_prop
 *
 * Purpose:     Modifies the vol property
 *
 * Return:      TRUE: Deltafs enabled
 *              FALSE: Deltafs not enabled
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
    hid_t fapl_id, hid_t dxpl_id, void **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    ret_value = (void *)1;

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
    hid_t dxpl_id, void **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    ret_value = (void *)1;

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_file_open() */

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
H5VL_deltafs_file_close(void *_file, hid_t dxpl_id, void **req)
{
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_file_close() */

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
    hid_t gcpl_id, hid_t gapl_id, hid_t dxpl_id, void **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    ret_value = (void *)1;

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_create() */

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
    const char *name, hid_t gapl_id, hid_t dxpl_id, void **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT
 
    ret_value = (void *)1;

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_open() */


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
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_close() */

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
H5VL_deltafs_attribute_create(void *_item, H5VL_loc_params_t loc_params,
    const char *name, hid_t acpl_id, hid_t H5_ATTR_UNUSED aapl_id,
    hid_t dxpl_id, void **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

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

    FUNC_ENTER_NOAPI_NOINIT

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

    FUNC_ENTER_NOAPI_NOINIT

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

    FUNC_ENTER_NOAPI_NOINIT

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

    FUNC_ENTER_NOAPI_NOINIT

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_attribute_close() */


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
    hid_t dcpl_id, hid_t dapl_id, hid_t dxpl_id, void **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    ret_value = (void *)1;

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
 *              November, 2016
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_dataset_open(void *_item,
    H5VL_loc_params_t H5_ATTR_UNUSED loc_params, const char *name,
    hid_t dapl_id, hid_t dxpl_id, void **req)
{
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT
 
    ret_value = (void *)1;

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_dataset_open() */


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
    hid_t file_space_id, hid_t dxpl_id, void *buf, void H5_ATTR_UNUSED **req)
{
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

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
 *              November, 2016
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5VL_deltafs_dataset_write(void *_dset, hid_t mem_type_id, hid_t mem_space_id,
    hid_t file_space_id, hid_t H5_ATTR_UNUSED dxpl_id,
    const void *buf, void H5_ATTR_UNUSED **req)
{
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_dataset_write() */

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
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_dataset_close() */

