/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Copyright by the Board of Trustees of the University of Illinois.         *
 * All rights reserved.                                                      *
 *                                                                           *
 * This file is part of HDF5.  The full HDF5 copyright notice, including     *
 * terms governing use, modification, and redistribution, is contained in    *
 * the files COPYING and Copyright.html.  COPYING can be found at the root   *
 * of the source code distribution tree; Copyright.html can be found at the  *
 * root level of an installed copy of the electronic HDF5 document set and   *
 * is linked from the top-level documents page.  It can also be found at     *
 * http://hdf.ncsa.uiuc.edu/HDF5/doc/Copyright.html.  If you do not have     *
 * access to either file, you may request a copy from hdfhelp@ncsa.uiuc.edu. *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* This program demonstrates how to translate an external link created on
 * a Windows machine into a format that a *nix machine can read.
 * This is done by registering a new traversal function for external links.
 *
 * This example is designed to be run on Unix and will create an external
 * link with a Windows-style path.  Using the traversal function below,
 * the example then successfully follows the external link.
 *
 * The external link will create a  file called "u2w/u2w_target.h5".
 * The example will fail if the directory u2w does not exist.
 */

#include "hdf5.h"
#include <stdlib.h>
#include <string.h>


/* "Windows to Unix" traversal function for external links
 *
 * Translates a filename stored in Unix format to Windows format by replacing
 * forward slashes with backslashes.
 * Makes no attempt to handle Windows drive names (e.g., "C:\"), spaces within
 * file names, quotes, etc.  These are left as an exercise for the user. :)
 * Note that this may not be necessary on your system; many Windows systems can
 * understand Unix paths.
 */
static hid_t elink_unix2win_trav(const char *link_name, hid_t cur_group, void * udata, size_t udata_size, hid_t lapl_id)
{
    hid_t         fid;
    char         *file_name;
    hbool_t       fname_alloc = 0;  /* Whether file_name has been allocated */
    char         *obj_name;
    char         *new_fname = NULL;     /* Buffer allocated to hold Unix file path */
    size_t        fname_len;
    htri_t        result;
    size_t        buf_size;             /* Size prefix buffer */
    size_t        start_pos;            /* Initial position in new_fname buffer */
    size_t        x;                    /* Counter variable */
    hid_t         ret_value = -1;

    printf("Converting Unix path to Windows path.\n");

    if(H5Lunpack_elink_val(udata, &file_name, &obj_name) < 0)
        goto error;
    fname_len = strlen(file_name);

    /* See if the external link prefix property is set */
    if((result = H5Pexist(lapl_id, H5L_ELINK_PREFIX_PROP)) < 0)
        goto error;

    /* If so, prepend it to the filename.  We assume that the prefix
     * is in the correct format for the current file system.
     */
    if(result > 0)
    {
        if(H5Pget_size(lapl_id, H5L_ELINK_PREFIX_PROP, &buf_size) < 0)
          goto error;

        /* Allocate a buffer to hold the filename plus prefix */
        new_fname = malloc(buf_size + fname_len + 1);

        /* Copy the prefix into the buffer */
        if(H5Pget(lapl_id, H5L_ELINK_PREFIX_PROP, new_fname) < 0)
          goto error;

        start_pos = buf_size - 1;
    }
    else
    {
        /* Allocate a buffer to hold just the filename */
        new_fname = malloc(fname_len + 1);
        start_pos = 0;
    }

    /* We should now copy file_name into new_fname starting at position pos.
     * We'll convert '/' characters into '\' characters as we go.
     */
    for(x=0; file_name[x] != '\0'; x++)
    {
        if(file_name[x] == '/')
            new_fname[x + start_pos] = '\\';
        else
            new_fname[x + start_pos] = file_name[x];
    }
    new_fname[x + start_pos] = '\0';

    /* Now open the file and object within it */
    if((fid = H5Fopen(new_fname, H5F_ACC_RDWR, H5P_DEFAULT)) < 0)
        goto error;
    ret_value = H5Oopen(fid, obj_name, lapl_id); /* If this fails, our return value will be negative. */
    if(H5Fclose(fid) < 0)
        goto error;

    /* Free file_name if it's been allocated */
    if(fname_alloc)
        free(file_name);

    return ret_value;

error:
    /* Free file_name if it's been allocated */
    if(new_fname)
        free(new_fname);
    return -1;
}

const H5L_class_t elink_unix2win_class[1] = {{
    H5L_LINK_CLASS_T_VERS,      /* H5L_class_t version       */
    H5L_TYPE_EXTERNAL,          /* Link type id number            */
    "unix2win external link",   /* Link class name for debugging  */
    NULL,                       /* Creation callback              */
    NULL,                       /* Move callback                  */
    NULL,                       /* Copy callback                  */
    elink_unix2win_trav,        /* The actual traversal function  */
    NULL,                       /* Deletion callback              */
    NULL                        /* Query callback                 */
}};


/* The example function.
 * Creates a file named "unix2win.h5" with an external link pointing to
 * the file "u2w/u2w_target.h5".
 *
 * Registers a new traversal function for external links and then
 * follows the external link to open the target file.
 */
static int
unix2win_example()
{
    hid_t	fid = (-1);     		/* File ID */
    hid_t	gid = (-1);     		/* Group ID */

    /* Create the target file. */
#ifdef WIN32
    if((fid=H5Fcreate("u2w\u2w_target.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT))<0) goto error;
#else
    if((fid=H5Fcreate("u2w/u2w_target.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT))<0) goto error;
#endif
    if(H5Fclose(fid) < 0) goto error;
    
    /* Create the source file with an external link in Windows format */
    if((fid=H5Fcreate("unix2win.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT))<0) goto error;

    /* Create the external link */
    if(H5Lcreate_external("u2w/../u2w/u2w_target.h5", "/", fid, "ext_link", H5P_DEFAULT, H5P_DEFAULT) < 0) goto error;

    /* If we are not on Windows, assume we are on a Unix-y filesystem and
     * follow the external link normally.
     * If we are on Windows, register the unix2win traversal function so
     * that external links can be traversed.
     */

#ifdef WIN32
    /* Register the elink_unix2win class defined above to replace default
     * external links
     */
    if(H5Lregister(elink_unix2win_class) < 0) goto error;
#endif

    /* Now follow the link */
    if((gid = H5Gopen(fid, "ext_link")) < 0) goto error;
    printf("Successfully followed external link.\n");

    /* Close the group and the file */
    if(H5Gclose(gid) <0) goto error;
    if(H5Fclose(fid) <0) goto error;

    return 0;

 error:
    printf("Error!\n");
    H5E_BEGIN_TRY {
    	H5Gclose (gid);
    	H5Fclose (fid);
    } H5E_END_TRY;
    return -1;
}


/* Main function
 *
 * Invokes the example function.
 */
int
main(void)
{
    int		ret;

    printf("Testing unix2win external links.\n");
    ret = unix2win_example();

    return ret;
}

