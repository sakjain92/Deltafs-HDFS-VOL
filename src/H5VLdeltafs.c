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
#define H5VL_DELTAFS_SEQ_LIST_LEN 64

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

/* Helper functions */
static herr_t H5VL_deltafs_file_close_helper(H5VL_deltafs_file_t *file);
static herr_t H5VL_deltafs_dataset_close_helper(H5VL_deltafs_dset_t *dset);
static herr_t H5VL_deltafs_group_close_helper(H5VL_deltafs_group_t *grp);

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

    hbool_t ret_value = FALSE;

    FUNC_ENTER_NOAPI_NOERR

    if (H5VL_DELTAFS_term == false)
        ret_value = (NULL != HDgetenv(H5VL_DELTAFS_ENABLE_ENV));

    FUNC_LEAVE_NOAPI(ret_value)
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
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT_NOERR

    /* "Forget" plugin id.  This should normally be called by the library
     * when it is closing the id, so no need to close it here. */
    H5VL_DELTAFS_g = -1;
    H5VL_DELTAFS_term = true;

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_term() */

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
H5VL_deltafs_file_struct_init(H5VL_deltafs_file_t *file, int fd,
        unsigned flags) {

    herr_t ret_value = SUCCEED;
    size_t magic_number = HDF5_VOL_DELATFS_FILE_MAGIC_NUMBER;
    FUNC_ENTER_NOAPI_NOINIT

    file->obj.item.file = file;
    file->obj.item.type = H5I_FILE;
    
    file->flags = flags;
    H5VL_DELTAFS_LHEAD_INIT(file->dlist_head);
    file->fd = fd;

    /* If file being created, file metadata needs to be written out */
    if (flags & H5F_ACC_TRUNC || flags & H5F_ACC_EXCL) {
        HDmemset(&file->fmd, 0, sizeof(file->fmd));
        file->fmd.magic_number = magic_number;
        
        /* At top of file the file metadata resides */
        file->fmd.num_groups = 0;
        file->fmd.write_offset = sizeof(file->fmd);
        file->dirty = true;
    } else {
        if (deltafs_pread(file->fd, &file->fmd, sizeof(file->fmd), 0) != sizeof(file->fmd))
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't read file")

        if (0 != HDmemcmp(&file->fmd.magic_number, &magic_number,
                sizeof(file->fmd.magic_number)))
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "bad/corrupted file")
        file->dirty = false;
    }

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
    int deltafs_flags;
    int fd = -1;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /*
     * Adjust bit flags by turning on the creation bit and making sure that
     * the EXCL or TRUNC bit is set.  All newly-created files are opened for
     * reading and writing.
     */
    if(0==(flags & (H5F_ACC_EXCL|H5F_ACC_TRUNC)))
        flags |= H5F_ACC_EXCL;      /*default*/
    flags |= H5F_ACC_RDWR | H5F_ACC_CREAT;

    deltafs_flags = O_RDWR;
    deltafs_flags |= flags & H5F_ACC_EXCL ? O_EXCL | O_CREAT :
        (flags & H5F_ACC_TRUNC ? O_TRUNC | O_CREAT : 0);

    /* Get information from the FAPL */
    if(NULL == (H5P_object_verify(fapl_id, H5P_FILE_ACCESS)))
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "not a file access property list")

    if (fcpl_id != H5P_DEFAULT && fcpl_id != H5P_FILE_CREATE_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported creation properties")

    /*
    if (dxpl_id != H5P_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported transfer properties")
    */

    if ((fd = deltafs_open(name, deltafs_flags, S_IRUSR | S_IWUSR)) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTOPENFILE, NULL, "can't open file %s", name)

    /* allocate the file object that is returned to the user */
    if(NULL == (file = H5FL_CALLOC(H5VL_deltafs_file_t)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, NULL, "can't allocate Deltafs file struct")
    
    if (H5VL_deltafs_file_struct_init(file, fd, flags) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, NULL, "error in file struct init")

    ret_value = (void *)file;

done:
    /* Cleanup on failure */
    if(NULL == ret_value) {
        
        /* Close file */
        if(file) {
            if(H5VL_deltafs_file_close_helper(file) < 0)
                HDONE_ERROR(H5E_FILE, H5E_CANTCLOSEFILE, NULL, "can't close file")
        } else if(fd >= 0) {
            if (0 != close(fd))
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
    int deltafs_flags =  (flags & H5F_ACC_RDWR) ? O_RDWR : O_RDONLY;
    int fd = -1;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /* Get information from the FAPL */
    if(NULL == H5P_object_verify(fapl_id, H5P_FILE_ACCESS))
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "not a file access property list")

    /*
    if (dxpl_id != H5P_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported creation/transfer properties")
    */

    /* TODO: If trunc flag set, need to delete all groups and datasets */
    if ((fd = deltafs_open(name, deltafs_flags, S_IRUSR | S_IWUSR)) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTOPENFILE, NULL, "can't open file")

    /* allocate the file object that is returned to the user */
    if(NULL == (file = H5FL_CALLOC(H5VL_deltafs_file_t)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, NULL, "can't allocate Deltafs file struct")

    if (H5VL_deltafs_file_struct_init(file, fd, flags) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, NULL, "error in file struct init")

    ret_value = (void *)file;

done:
    /* Cleanup on failure */
    if(NULL == ret_value) {
        if(file) {
            if(H5VL_deltafs_file_close_helper(file) < 0)
                HDONE_ERROR(H5E_FILE, H5E_CANTCLOSEFILE, NULL, "can't close file")
        } else if(fd >= 0) {
            if (0 != close(fd))
                HDONE_ERROR(H5E_FILE, H5E_CLOSEERROR, NULL, "can't close file")
        }     
    } /* end if */

    FUNC_LEAVE_NOAPI(ret_value)

} /* end H5VL_deltafs_file_open() */

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
    H5VL_deltafs_dset_t *dset = NULL;
    H5VL_deltafs_dset_t *tempdset;
    char *buf = NULL;
    size_t buf_size = 0, buf_offset = 0;
    size_t prev_end_offset = (size_t)-1;
    int ret;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(file);

    /* Write down the file metadata */
    if (file->dirty) {
        /* 
         * If first dataset that is dirty starts just below file metadata,
         * then write them together
         */
        errno = 0;
        if (NULL == (dset = H5VL_DELTAFS_LGET_FRONT(file->dlist_head)) ||
                dset->dmd->offset != sizeof(file->fmd)) {
            if ((ret = deltafs_pwrite(file->fd, &file->fmd, sizeof(file->fmd), 0)) != sizeof(file->fmd))
                HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write file:%d, size: %ld, ret: %d, errno: %d", file->fd, sizeof(file->fmd), ret, errno)
            file->dirty = false;
        } else {
            buf_size += sizeof(file->fmd);
        }
    }

    /* 
     * Write down all the datasets. They should be consecutive
     * TODO: We don't allow modification to existing datasets currently
     * Also, this constraint will not allow mixed read/writes
     */
    H5VL_DELTAFS_LFOR_EACH(file->dlist_head, dset) {
            if (dset->dirty == false)
                continue;

            HDassert(prev_end_offset == (size_t)-1 || prev_end_offset == dset->dmd->offset);

            buf_size += dset->buf_size;
            prev_end_offset = dset->dmd->offset + dset->buf_size;
    }

    if (buf_size == 0)
        goto done;

    if(NULL == (buf = (char *)H5MM_malloc(buf_size)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, FAIL, "can't allocate space for global pool handle")

    /* TODO: Scatter gather in deltafs would help remove this double copy */
    if (file->dirty) {
        HDmemcpy(&buf[buf_offset], &file->fmd, sizeof(file->fmd));
        buf_offset += sizeof(file->fmd);
        file->dirty = false;
    }

    H5VL_DELTAFS_LFOR_EACH(file->dlist_head, dset) {
        if (dset->dirty == false)
            continue;
        HDmemcpy(&buf[buf_offset], &dset->buf, dset->buf_size);
        buf_offset += dset->buf_size;
        assert(buf_offset <= buf_size);
    }

    if (deltafs_pwrite(file->fd, buf, buf_size, 0) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't write file")
    
done:
    if(file->fd >= 0)
        if (0 != close(file->fd))
            HGOTO_ERROR(H5E_FILE, H5E_CLOSEERROR, FAIL, "can't close file")

    H5VL_DELTAFS_LFOR_EACH_SAFE(file->dlist_head , dset, tempdset) {
        H5VL_deltafs_dataset_close_helper(dset);    
    } H5VL_DELTAFS_LFOR_EACH_SAFE_END

    file = H5FL_FREE(H5VL_deltafs_file_t, file);

    H5MM_xfree(buf);

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

    /* TODO: Flush file ? */

    /* Close the file */
    if(H5VL_deltafs_file_close_helper(file) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_CANTCLOSEFILE, FAIL, "can't close file")

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_file_close() */

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
                            size_t *index)
{
    H5VL_deltafs_file_t *file = item->file;
    size_t i;
    size_t gidx = (size_t)-1;
    herr_t ret_value = SUCCEED;
    
    FUNC_ENTER_NOAPI_NOINIT

    HDassert(item);
    HDassert(name);
    HDassert(index);

    if (item->type != H5I_FILE)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL,
                "multiple group hierachy not supported")

    if (HDstrlen(name) + 1 > HDF5_VOL_DELTAFS_MAX_NAME)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "group name too long")

    /* TODO: Can use name to get index e.g Step#1 */
    for (i = 0; i < file->fmd.num_groups; i++) {
        if (HDstrcmp(file->fmd.gmd[i].name, name) == 0) {
            gidx = i;
            break;
        }
    }

    if (gidx == (size_t)-1)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "group not found")

    *index = gidx;

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_group_index() */


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
H5VL_deltafs_group_create_helper(H5VL_deltafs_file_t *file, const char *name)
{
    H5VL_deltafs_group_t *grp = NULL;
    H5VL_deltafs_group_t *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(file->flags & H5F_ACC_RDWR);

    if (HDstrlen(name) + 1 > HDF5_VOL_DELTAFS_MAX_NAME)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, NULL, "group name too long")

    if (file->fmd.num_groups == HDF5_VOL_DELTAFS_MAX_GROUP)
        HGOTO_ERROR(H5E_RESOURCE, H5E_NOSPACE, NULL, "max number of groups created")

    /* Allocate the group object that is returned to the user */
    if(NULL == (grp = H5FL_CALLOC(H5VL_deltafs_group_t)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate Deltafs group struct")
    
    grp->obj.item.type = H5I_GROUP;
    grp->obj.item.file = file;
    grp->index = file->fmd.num_groups++;

    HDstrcpy(file->fmd.gmd[grp->index].name, name);
    file->fmd.gmd[grp->index].num_dsets = 0;
    file->dirty = true;
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
    size_t gidx;
    H5VL_deltafs_group_t *grp = NULL;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /* Check for write access */
    if(!(item->file->flags & H5F_ACC_RDWR))
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "no write intent on file")

    if (gcpl_id != H5P_DEFAULT && gcpl_id != H5P_GROUP_CREATE_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported creation properties")

    if (gapl_id != H5P_DEFAULT && gapl_id != H5P_GROUP_ACCESS_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported access properties")

    if(H5VL_deltafs_get_group_index(item, name, &gidx) >= 0)
            HGOTO_ERROR(H5E_SYM, H5E_BADVALUE, NULL, "group name exists")

    if (NULL == (grp = H5VL_deltafs_group_create_helper(item->file, name)))
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
H5VL_deltafs_group_open_helper(H5VL_deltafs_file_t *file, size_t gidx)
{
    H5VL_deltafs_group_t *grp = NULL;
    H5VL_deltafs_group_t *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    /* Allocate the group object that is returned to the user */
    if(NULL == (grp = H5FL_CALLOC(H5VL_deltafs_group_t)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate Deltafs group struct")
    
    grp->obj.item.type = H5I_GROUP;
    grp->obj.item.file = file;
    grp->index = gidx;
    
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
    const char *name, hid_t gapl_id, hid_t H5_ATTR_UNUSED dxpl_id,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    H5VL_deltafs_group_t *grp = NULL;
    size_t gidx;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    if (H5VL_OBJECT_BY_ADDR == loc_params.type)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, NULL, "unsupported location parameter")

    if (gapl_id != H5P_DEFAULT /*|| dxpl_id != H5P_DEFAULT */)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported creation/transfer properties")

    /* Open using name parameter */
    if(H5VL_deltafs_get_group_index(item, name, &gidx) < 0)
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
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT_NOERR

    HDassert(grp);

    grp = H5FL_FREE(H5VL_deltafs_group_t, grp);

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
                            size_t *didx_out, size_t *gidx_out, hbool_t create_new)
{
    H5VL_deltafs_file_t *file = item->file;
    H5VL_deltafs_group_t *grp;
    size_t i;
    size_t gidx = (size_t)-1, didx = (size_t)-1;
    H5VL_deltafs_dmd_t *dmd;
    H5VL_deltafs_gmd_t *gmd;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(item);
    HDassert(name);
    HDassert(gidx);
    HDassert(didx);

    /* TODO: Support opening of dataset given full path */
    if (item->type != H5I_GROUP)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL,
                "multiple group hierachy not supported")

    grp = (H5VL_deltafs_group_t *)item;
    gidx = grp->index;

    if (HDstrlen(name) + 1 > HDF5_VOL_DELTAFS_MAX_NAME)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "group name too long")

    /* TODO: Can use name to get index e.g Step#1 */
    for (i = 0; i < file->fmd.gmd[gidx].num_dsets; i++) {
        if (HDstrcmp(file->fmd.gmd[gidx].dmd[i].name, name) == 0) {
            didx = i;
            break;
        }
    }

    if (didx == (size_t)-1 && create_new == false) {
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "dataset not found")
    } else if (didx != (size_t)-1 && create_new == true) {
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "dataset already exists")
    } else if (create_new == true) {
        gmd = &file->fmd.gmd[gidx];
        didx = gmd->num_dsets++;
        dmd = &gmd->dmd[didx];
        HDstrcpy(dmd->name, name);
        file->dirty = true;
    }
        
    *didx_out = didx;
    *gidx_out = gidx;

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
    H5VL_deltafs_dset_t *dset = NULL;
    H5P_genplist_t *plist = NULL;      /* Property list pointer */
    hid_t type_id, space_id;
    size_t gidx, didx;
    size_t type_size = 0;
    size_t elem_size = 0;
    size_t space_size = 0;
    int ndims;
    hsize_t dim[H5S_MAX_RANK];
    int i;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

     
    /* Check for write access */
    if(!(file->flags & H5F_ACC_RDWR))
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "no write intent on file")

    if (dapl_id != H5P_DEFAULT && dapl_id != H5P_DATASET_ACCESS_DEFAULT)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported access properties")

    /* Get the dcpl plist structure */
    if(NULL == (plist = (H5P_genplist_t *)H5I_object(dcpl_id)))
        HGOTO_ERROR(H5E_ATOM, H5E_BADATOM, NULL, "can't find object for ID")

    /* get creation properties */
    if(H5P_get(plist, H5VL_PROP_DSET_TYPE_ID, &type_id) < 0)
        HGOTO_ERROR(H5E_PLIST, H5E_CANTGET, NULL, "can't get property value for datatype id")
    if(H5P_get(plist, H5VL_PROP_DSET_SPACE_ID, &space_id) < 0)
        HGOTO_ERROR(H5E_PLIST, H5E_CANTGET, NULL, "can't get property value for space id")

    if (H5VL_deltafs_get_dataset_index(item, name, &didx, &gidx, true) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "couldn't create dataset")

    /* Allocate the dataset object that is returned to the user */
    if(NULL == (dset = H5FL_CALLOC(H5VL_deltafs_dset_t)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate Deltafs dataset struct")

    dset->obj.item.type = H5I_DATASET;
    dset->obj.item.file = item->file;
    dset->gidx = gidx;
    dset->didx = didx;
    dset->type_id = FAIL;
    dset->space_id = FAIL;
    dset->dirty = false;
    dset->buf = NULL;
    dset->buf_size = 0;
    dset->is_buf_read = false;
    dset->rc = 1;
    dset->dmd = &file->fmd.gmd[gidx].dmd[didx];
    H5VL_DELTAFS_LELEM_INIT(dset);

    if((dset->type_id = H5Tcopy(type_id)) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_CANTCOPY, NULL, "failed to copy datatype")
    if((dset->space_id = H5Scopy(space_id)) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_CANTCOPY, NULL, "failed to copy dataspace")
    if(H5Sselect_all(dset->space_id) < 0)
        HGOTO_ERROR(H5E_DATASPACE, H5E_CANTDELETE, NULL, "can't change selection")

    /* Get dataspace extent */
    if((ndims = H5Sget_simple_extent_ndims(dset->space_id)) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, NULL, "can't get number of dimensions")
    if(ndims != H5Sget_simple_extent_dims(dset->space_id, dim, NULL))
        HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, NULL, "can't get dimensions")
	if((type_size = H5Tget_size(dset->type_id)) == 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTGET, NULL, "can't get dimensions")

    if(H5Tencode(type_id, NULL, &type_size) < 0)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "can't determine serialized length of datatype")

    if(H5Sencode(space_id, NULL, &space_size) < 0)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "can't determine serialized length of dataaspace")

    if((elem_size = H5Tget_size(dset->type_id)) == 0)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "can't determine size of elem")

    dset->buf_size = 1;
	for (i = 0; i < ndims; i++)
		dset->buf_size *= dim[i];
	dset->buf_size *= elem_size;
    dset->buf_size += type_size + space_size;

    if(NULL == (dset->buf = (char *)H5MM_malloc(dset->buf_size)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate buffer")

    dset->dmd->type_size = type_size;
    dset->dmd->space_size = space_size;
    dset->dmd->size = dset->buf_size;
    dset->dmd->offset = file->fmd.write_offset;
    file->fmd.write_offset += dset->buf_size;
    file->dirty = true;

    /* Encode datatype */
    if(H5Tencode(type_id, &dset->buf[0], &type_size) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTENCODE, NULL, "can't serialize datatype")

    /* Encode dataspace */
    if(H5Sencode(space_id, &dset->buf[type_size], &space_size) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTENCODE, NULL, "can't serialize dataaspace")

    dset->dirty = true;
    dset->rc++;
    H5VL_DELTAFS_LADD_TAIL(item->file->dlist_head, dset);

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
 *              November, 2016
 *
 *-------------------------------------------------------------------------
 */
static void *
H5VL_deltafs_dataset_open(void *_item,
    H5VL_loc_params_t loc_params, const char *name,
    hid_t dapl_id, hid_t H5_ATTR_UNUSED dxpl_id, void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_item_t *item = (H5VL_deltafs_item_t *)_item;
    H5VL_deltafs_file_t *file = item->file;
    H5VL_deltafs_dmd_t *dmd = NULL;
    H5VL_deltafs_dset_t *dset = NULL;
    size_t gidx, didx;
    void *ret_value = NULL;

    FUNC_ENTER_NOAPI_NOINIT

    if (H5VL_OBJECT_BY_ADDR == loc_params.type)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, NULL, "unsupported location parameter")

    if (dapl_id != H5P_DEFAULT /*|| dxpl_id != H5P_DEFAULT*/)
        HGOTO_ERROR(H5E_ARGS, H5E_BADTYPE, NULL, "unsupported access/transfer properties")

    if (H5VL_deltafs_get_dataset_index(item, name, &didx, &gidx, false) < 0)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, NULL, "dataset name invalid")

    /* Allocate the dataset object that is returned to the user */
    if(NULL == (dset = H5FL_CALLOC(H5VL_deltafs_dset_t)))
        HGOTO_ERROR(H5E_RESOURCE, H5E_CANTALLOC, NULL, "can't allocate Deltafs dataset struct")
    dset->obj.item.type = H5I_DATASET;
    dset->obj.item.file = item->file;
    dset->type_id = FAIL;
    dset->space_id = FAIL;
    dset->gidx = gidx;
    dset->didx = didx;
    dset->dirty = false;
    dset->buf = NULL;
    dset->buf_size = dmd->size;
    dset->is_buf_read = false;
    dset->rc = 1;
    dset->dmd = &file->fmd.gmd[gidx].dmd[didx];
    H5VL_DELTAFS_LELEM_INIT(dset);

    if (dset->dmd->type_size + dset->dmd->space_size > dset->dmd->size)
        HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, NULL, "corrupted file")

    /* TODO: If the dset is present in dlist in file, use that */
    if(NULL == (dset->buf = (char *)H5MM_malloc(dset->buf_size)))
        HGOTO_ERROR(H5E_FILE, H5E_CANTALLOC, NULL, "can't allocate space for buffer")

    if (deltafs_pread(file->fd, &dset->buf, dset->buf_size, (int)dset->dmd->offset) != (int)dset->buf_size)
        HGOTO_ERROR(H5E_FILE, H5E_BADFILE, NULL, "can't read file")

    dset->is_buf_read = true;

    /* Decode datatype and space id */
    if((dset->type_id = H5Tdecode(&dset->buf[0])) < 0)
        HGOTO_ERROR(H5E_ARGS, H5E_CANTDECODE, NULL, "can't deserialize datatype")
    if((dset->space_id = H5Pdecode(&dset->buf[dset->dmd->type_size])) < 0)
        HGOTO_ERROR(H5E_ARGS, H5E_CANTDECODE, NULL, "can't deserialize dataspace")
    if(H5Sselect_all(dset->space_id) < 0)
        HGOTO_ERROR(H5E_DATASPACE, H5E_CANTDELETE, NULL, "can't change selection")

    dset->rc++;
    H5VL_DELTAFS_LADD_TAIL(file->dlist_head, dset);

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
H5VL_deltafs_xfer(void *_dest_buf, H5S_t *dest_space, const void *_src_buf,
        H5S_t *src_space, size_t type_size, size_t total_size)
{
    uint8_t *dest_buf = (uint8_t *)_dest_buf;
    const uint8_t *src_buf = (const uint8_t *)_src_buf;
    H5S_sel_iter_t src_sel_iter;                /* Selection iteration info */
    hbool_t src_sel_iter_init = FALSE;      /* Selection iteration info has been initialized */
    H5S_sel_iter_t dest_sel_iter;
    hbool_t dest_sel_iter_init = FALSE;
    size_t src_nseq, dest_nseq;
    size_t src_nelem, dest_nelem;
    size_t src_nseq_unread = 0;
    size_t dest_nseq_unread = 0;
    hsize_t src_off[H5VL_DELTAFS_SEQ_LIST_LEN];
    size_t src_len[H5VL_DELTAFS_SEQ_LIST_LEN];
    hsize_t dest_off[H5VL_DELTAFS_SEQ_LIST_LEN];
    size_t dest_len[H5VL_DELTAFS_SEQ_LIST_LEN];
    size_t src_i, dest_i;
    size_t total_xfer = 0;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    HDassert(src_buf && dest_buf);
    HDassert(src_space && dest_space);

    if(H5S_select_iter_init(&src_sel_iter, src_space, type_size) < 0)
        HGOTO_ERROR(H5E_DATASPACE, H5E_CANTINIT, FAIL, "unable to initialize selection iterator")
    src_sel_iter_init = TRUE;

     if(H5S_select_iter_init(&dest_sel_iter, dest_space, type_size) < 0)
        HGOTO_ERROR(H5E_DATASPACE, H5E_CANTINIT, FAIL, "unable to initialize selection iterator")
    dest_sel_iter_init = TRUE;

    /* Generate sequences from the file space until finished */
    do {
        /* Get the sequences of bytes */
        if(src_nseq_unread == 0 && 
                H5S_SELECT_GET_SEQ_LIST(src_space, 0, &src_sel_iter,
                    (size_t)H5VL_DELTAFS_SEQ_LIST_LEN, (size_t)-1, &src_nseq, &src_nelem, src_off, src_len) < 0)
            HGOTO_ERROR(H5E_DATASPACE, H5E_CANTGET, FAIL, "sequence length generation failed")

        if(dest_nseq_unread == 0 && 
                H5S_SELECT_GET_SEQ_LIST(dest_space, 0, &dest_sel_iter,
                    (size_t)H5VL_DELTAFS_SEQ_LIST_LEN, (size_t)-1, &dest_nseq, &dest_nelem, dest_off, dest_len) < 0)
            HGOTO_ERROR(H5E_DATASPACE, H5E_CANTGET, FAIL, "sequence length generation failed")

        /* Copy wrt to offsets/lengths */
        src_i = dest_i = 0;
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
                src_len[dest_i] -= xfer_len;
                src_off[dest_i] += xfer_len;
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
    hid_t file_space_id, hid_t H5_ATTR_UNUSED dxpl_id, void *buf,
    void H5_ATTR_UNUSED **req)
{
    H5VL_deltafs_dset_t *dset = (H5VL_deltafs_dset_t *)_dset;
    H5VL_deltafs_file_t *file = dset->obj.item.file;
    H5VL_deltafs_dmd_t *dmd = &file->fmd.gmd[dset->gidx].dmd[dset->didx];
    hid_t real_file_space_id;
    hid_t real_mem_space_id;
    H5S_t *file_space = NULL;
    H5S_t *mem_space = NULL;
    size_t type_size;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    /*
     * TODO: We don't support conversion currently. Type size should be same
     * of memory and that in the file
     */
    if (H5Tequal(mem_type_id, dset->type_id) != true)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "improper mem type")

    if((type_size = H5Tget_size(mem_type_id)) == 0)
        HGOTO_ERROR(H5E_DATATYPE, H5E_CANTGET, FAIL, "can't get source type size")

    /* Get "real" space ids */
    if(file_space_id == H5S_ALL)
        real_file_space_id = dset->space_id;
    else
        real_file_space_id = file_space_id;
    if(mem_space_id == H5S_ALL)
        real_mem_space_id = real_file_space_id;
    else
        real_mem_space_id = mem_space_id;

     /* Get file dataspace object */
    if(NULL == (file_space = (H5S_t *)H5I_object(real_file_space_id)))
            HGOTO_ERROR(H5E_ATOM, H5E_BADATOM, FAIL, "can't find object for ID");

    if(NULL == (mem_space = (H5S_t *)H5I_object(real_mem_space_id)))
            HGOTO_ERROR(H5E_ATOM, H5E_BADATOM, FAIL, "can't find object for ID");

    if (dset->is_buf_read == false) {
   
        if (deltafs_pread(file->fd, &dset->buf, dset->buf_size, (int)dset->dmd->offset) != (int)dset->buf_size)
            HGOTO_ERROR(H5E_FILE, H5E_BADFILE, FAIL, "can't read file")

        dset->is_buf_read = false;
    }

    /* Transfer from dset buf to buffer */
    if(H5VL_deltafs_xfer((void *)buf, mem_space,
                (void *)&dset->buf[dmd->type_size + dmd->space_size],
                file_space, type_size, dset->buf_size - dmd->type_size - dmd->space_size) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTINIT, FAIL, "can't read from memory")

done:
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
    H5VL_deltafs_dset_t *dset = (H5VL_deltafs_dset_t *)_dset;
    H5VL_deltafs_file_t *file = dset->obj.item.file;
    H5VL_deltafs_dmd_t *dmd = dset->dmd;
    hid_t real_file_space_id;
    hid_t real_mem_space_id;
    H5S_t *file_space = NULL;
    H5S_t *mem_space = NULL;
    size_t type_size;
    herr_t ret_value = SUCCEED;

    FUNC_ENTER_NOAPI_NOINIT

    /* Check for write access */
    if(!(file->flags & H5F_ACC_RDWR))
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "no write intent on file")

    /*
     * TODO: We don't support conversion currently. Type size should be same
     * of memory and that in the file
     */
    if (H5Tequal(mem_type_id, dset->type_id) != true)
        HGOTO_ERROR(H5E_FILE, H5E_BADVALUE, FAIL, "improper mem type")

    if((type_size = H5Tget_size(mem_type_id)) == 0)
        HGOTO_ERROR(H5E_DATATYPE, H5E_CANTGET, FAIL, "can't get source type size")

    /* Get "real" space ids */
    if(file_space_id == H5S_ALL)
        real_file_space_id = dset->space_id;
    else
        real_file_space_id = file_space_id;
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
    if(H5VL_deltafs_xfer((void *)&dset->buf[dmd->type_size + dmd->space_size],
                file_space, (const void *)buf, mem_space, type_size, dset->buf_size -
                dmd->type_size - dmd->space_size) < 0)
        HGOTO_ERROR(H5E_DATASET, H5E_CANTINIT, FAIL, "can't read from memory")

    dset->dirty = true;

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5VL_deltafs_dataset_write() */

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

    if(--dset->rc == 0) {
        /* Free dataset data structures */
        if(dset->type_id != FAIL && H5I_dec_app_ref(dset->type_id) < 0)
            HDONE_ERROR(H5E_DATASET, H5E_CANTDEC, FAIL, "failed to close datatype")
        if(dset->space_id != FAIL && H5I_dec_app_ref(dset->space_id) < 0)
            HDONE_ERROR(H5E_DATASET, H5E_CANTDEC, FAIL, "failed to close dataspace")
        
        if(dset->buf)
            H5MM_xfree(dset->buf);

        dset = H5FL_FREE(H5VL_deltafs_dset_t, dset);
    } /* end if */

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
