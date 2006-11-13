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

/*-------------------------------------------------------------------------
 *
 * Created:		H5Gcompact.c
 *			Sep  5 2005
 *			Quincey Koziol <koziol@ncsa.uiuc.edu>
 *
 * Purpose:		Functions for handling compact storage.
 *
 *-------------------------------------------------------------------------
 */
#define H5G_PACKAGE		/*suppress error about including H5Gpkg	  */


/* Packages needed by this file... */
#include "H5private.h"		/* Generic Functions			*/
#include "H5Eprivate.h"		/* Error handling		  	*/
#include "H5Gpkg.h"		/* Groups		  		*/
#include "H5Iprivate.h"		/* IDs			  		*/
#include "H5MMprivate.h"	/* Memory management			*/

/* Private typedefs */

/* User data for link message iteration when building link table */
typedef struct {
    H5G_link_table_t *ltable;   /* Pointer to link table to build */
    size_t curr_lnk;            /* Current link to operate on */
} H5G_compact_ud1_t;

/* User data for deleting a link in the link messages */
typedef struct {
    /* downward */
    const char *name;           /* Name to search for */
    H5F_t       *file;          /* File that object header is located within */
    hid_t       dxpl_id;        /* DXPL during insertion */

    /* upward */
    H5G_obj_t *obj_type;        /* Type of object deleted */
} H5G_compact_ud2_t;

/* User data for link message iteration when querying object info */
typedef struct {
    /* downward */
    const char *name;           /* Name to search for */
    H5F_t       *file;          /* File that object header is located within */
    hid_t       dxpl_id;        /* DXPL during insertion */

    /* upward */
    H5G_stat_t *statbuf;        /* Stat buffer for info */
} H5G_compact_ud3_t;

/* User data for link message iteration when querying object location */
typedef struct {
    /* downward */
    const char *name;           /* Name to search for */

    /* upward */
    H5O_link_t *lnk;            /* Link struct to fill in */
    hbool_t found;              /* Flag to indicate that the object was found */
} H5G_compact_ud4_t;

/* User data for link message iteration when querying soft link value */
typedef struct {
    /* downward */
    const char *name;           /* Name to search for */
    size_t size;                /* Buffer size for link value */

    /* upward */
    char *buf;                  /* Buffer to fill with link value */
} H5G_compact_ud5_t;

/* Private macros */

/* PRIVATE PROTOTYPES */
static herr_t H5G_compact_build_table_cb(const void *_mesg, unsigned idx, void *_udata);
static herr_t H5G_compact_build_table(H5O_loc_t *oloc, hid_t dxpl_id,
    const H5O_linfo_t *linfo, H5L_index_t idx_type, H5_iter_order_t order,
    H5G_link_table_t *ltable);


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_build_table_cb
 *
 * Purpose:	Callback routine for searching 'link' messages for a particular
 *              name.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *		koziol@ncsa.uiuc.edu
 *		Sep  5 2005
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5G_compact_build_table_cb(const void *_mesg, unsigned UNUSED idx, void *_udata)
{
    const H5O_link_t *lnk = (const H5O_link_t *)_mesg;  /* Pointer to link */
    H5G_compact_ud1_t *udata = (H5G_compact_ud1_t *)_udata;     /* 'User data' passed in */
    herr_t ret_value=H5O_ITER_CONT;             /* Return value */

    FUNC_ENTER_NOAPI_NOINIT(H5G_compact_build_table_cb)

    /* check arguments */
    HDassert(lnk);
    HDassert(udata);
    HDassert(udata->curr_lnk < udata->ltable->nlinks);

    /* Copy link message into table */
    if(NULL == H5O_copy(H5O_LINK_ID, lnk, &(udata->ltable->lnks[udata->curr_lnk])))
        HGOTO_ERROR(H5E_SYM, H5E_CANTCOPY, H5O_ITER_ERROR, "can't copy link message")

    /* Increment current link entry to operate on */
    udata->curr_lnk++;

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_build_table_cb() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_build_table
 *
 * Purpose:     Builds a table containing a sorted (alphabetically) list of
 *              links for a group
 *
 * Return:	Success:        Non-negative
 *		Failure:	Negative
 *
 * Programmer:	Quincey Koziol
 *	        Sep  6, 2005
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5G_compact_build_table(H5O_loc_t *oloc, hid_t dxpl_id, const H5O_linfo_t *linfo,
    H5L_index_t idx_type, H5_iter_order_t order, H5G_link_table_t *ltable)
{
    herr_t	ret_value = SUCCEED;    /* Return value */

    FUNC_ENTER_NOAPI_NOINIT(H5G_compact_build_table)

    /* Sanity check */
    HDassert(oloc);
    HDassert(linfo);
    HDassert(ltable);

    /* Set size of table */
    H5_CHECK_OVERFLOW(linfo->nlinks, hsize_t, size_t);
    ltable->nlinks = (size_t)linfo->nlinks;

    /* Allocate space for the table entries */
    if(ltable->nlinks > 0) {
        H5G_compact_ud1_t udata;               /* User data for iteration callback */

        if((ltable->lnks = H5MM_malloc(sizeof(H5O_link_t) * ltable->nlinks)) == NULL)
            HGOTO_ERROR(H5E_RESOURCE, H5E_NOSPACE, FAIL, "memory allocation failed")

        /* Set up user data for iteration */
        udata.ltable = ltable;
        udata.curr_lnk = 0;

        /* Iterate through the link messages, adding them to the table */
        if(H5O_iterate(oloc, H5O_LINK_ID, H5G_compact_build_table_cb, &udata, dxpl_id) < 0)
            HGOTO_ERROR(H5E_SYM, H5E_NOTFOUND, FAIL, "error iterating over link messages")

        /* Sort link table in correct iteration order */
        if(idx_type == H5L_INDEX_NAME) {
            if(order == H5_ITER_INC)
                HDqsort(ltable->lnks, ltable->nlinks, sizeof(H5O_link_t), H5G_link_cmp_name_inc);
            else if(order == H5_ITER_DEC)
                HDqsort(ltable->lnks, ltable->nlinks, sizeof(H5O_link_t), H5G_link_cmp_name_dec);
            else
                HDassert(order == H5_ITER_NATIVE);
        } /* end if */
        else {
            HDassert(idx_type == H5L_INDEX_CRT_ORDER);
            if(order == H5_ITER_INC)
                HDqsort(ltable->lnks, ltable->nlinks, sizeof(H5O_link_t), H5G_link_cmp_corder_inc);
            else if(order == H5_ITER_DEC)
                HDqsort(ltable->lnks, ltable->nlinks, sizeof(H5O_link_t), H5G_link_cmp_corder_dec);
            else
                HDassert(order == H5_ITER_NATIVE);
        } /* end else */
    } /* end if */
    else
        ltable->lnks = NULL;

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_build_table() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_insert
 *
 * Purpose:	Insert a new symbol into the table described by GRP_ENT in
 *		file F.	 The name of the new symbol is NAME and its symbol
 *		table entry is OBJ_ENT.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *		koziol@ncsa.uiuc.edu
 *		Sep  6 2005
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5G_compact_insert(H5O_loc_t *grp_oloc, H5O_link_t *obj_lnk,
    hid_t dxpl_id)
{
    herr_t     ret_value = SUCCEED;       /* Return value */

    FUNC_ENTER_NOAPI(H5G_compact_insert, FAIL)

    /* check arguments */
    HDassert(grp_oloc && grp_oloc->file);
    HDassert(obj_lnk);

    /* Insert link message into group */
    if(H5O_modify(grp_oloc, H5O_LINK_ID, H5O_NEW_MESG, 0, H5O_UPDATE_TIME, obj_lnk, dxpl_id) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_CANTINIT, FAIL, "can't create message")

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_insert() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_get_name_by_idx
 *
 * Purpose:     Returns the name of objects in the group by giving index.
 *
 * Return:	Success:        Non-negative, length of name
 *		Failure:	Negative
 *
 * Programmer:	Quincey Koziol
 *	        Sep  6, 2005
 *
 *-------------------------------------------------------------------------
 */
ssize_t
H5G_compact_get_name_by_idx(H5O_loc_t *oloc, hid_t dxpl_id,
    const H5O_linfo_t *linfo, H5L_index_t idx_type, H5_iter_order_t order,
    hsize_t idx, char* name, size_t size)
{
    H5G_link_table_t    ltable = {0, NULL};         /* Link table */
    ssize_t		ret_value;      /* Return value */

    FUNC_ENTER_NOAPI(H5G_compact_get_name_by_idx, FAIL)

    /* Sanity check */
    HDassert(oloc);

    /* Build table of all link messages */
    if(H5G_compact_build_table(oloc, dxpl_id, linfo, idx_type, order, &ltable) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_CANTINIT, FAIL, "can't create link message table")

    /* Check for going out of bounds */
    if(idx >= ltable.nlinks)
	HGOTO_ERROR(H5E_ARGS, H5E_BADVALUE, FAIL, "index out of bound")

    /* Get the length of the name */
    ret_value = (ssize_t)HDstrlen(ltable.lnks[idx].name);

    /* Copy the name into the user's buffer, if given */
    if(name) {
        HDstrncpy(name, ltable.lnks[idx].name, MIN((size_t)(ret_value + 1), size));
        if((size_t)ret_value >= size)
            name[size - 1]='\0';
    } /* end if */

done:
    /* Release link table */
    if(ltable.lnks)
        /* Free link table information */
        if(H5G_link_release_table(&ltable) < 0)
            HDONE_ERROR(H5E_SYM, H5E_CANTFREE, FAIL, "unable to release link table")

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_get_name_by_idx() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_get_type_by_idx
 *
 * Purpose:     Returns the type of objects in the group by giving index.
 *
 * Return:	Success:        Non-negative
 *		Failure:	Negative
 *
 * Programmer:	Quincey Koziol
 *	        Sep 12, 2005
 *
 *-------------------------------------------------------------------------
 */
H5G_obj_t
H5G_compact_get_type_by_idx(H5O_loc_t *oloc, hid_t dxpl_id, const H5O_linfo_t *linfo,
    hsize_t idx)
{
    H5G_link_table_t    ltable = {0, NULL};         /* Link table */
    H5G_obj_t		ret_value;      /* Return value */

    FUNC_ENTER_NOAPI(H5G_compact_get_type_by_idx, H5G_UNKNOWN)

    /* Sanity check */
    HDassert(oloc);

    /* Build table of all link messages */
    if(H5G_compact_build_table(oloc, dxpl_id, linfo, H5L_INDEX_NAME, H5_ITER_INC, &ltable) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_CANTINIT, H5G_UNKNOWN, "can't create link message table")

    /* Check for going out of bounds */
    if(idx >= ltable.nlinks)
	HGOTO_ERROR(H5E_ARGS, H5E_BADRANGE, H5G_UNKNOWN, "index out of bound")

    /* Determine type of object */
    if(ltable.lnks[idx].type == H5L_TYPE_SOFT)
        ret_value = H5G_LINK;
    else if(ltable.lnks[idx].type >= H5L_TYPE_UD_MIN)
        ret_value = H5G_UDLINK;
    else if(ltable.lnks[idx].type == H5L_TYPE_HARD){
        H5O_loc_t tmp_oloc;             /* Temporary object location */

        /* Build temporary object location */
        tmp_oloc.file = oloc->file;
        tmp_oloc.addr = ltable.lnks[idx].u.hard.addr;

        /* Get the type of the object */
        if((ret_value = H5O_obj_type(&tmp_oloc, dxpl_id)) == H5G_UNKNOWN)
            HGOTO_ERROR(H5E_SYM, H5E_BADTYPE, H5G_UNKNOWN, "can't determine object type")
    } else {
        HGOTO_ERROR(H5E_SYM, H5E_BADTYPE, H5G_UNKNOWN, "unknown link type")
    } /* end else */

done:
    /* Release link table */
    if(ltable.lnks)
        /* Free link table information */
        if(H5G_link_release_table(&ltable) < 0)
            HDONE_ERROR(H5E_SYM, H5E_CANTFREE, H5G_UNKNOWN, "unable to release link table")

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_get_type_by_idx() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_remove_cb
 *
 * Purpose:	Callback routine for deleting 'link' message for a particular
 *              name.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *		koziol@ncsa.uiuc.edu
 *		Sep  5 2005
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5G_compact_remove_cb(const void *_mesg, unsigned UNUSED idx, void *_udata)
{
    const H5O_link_t *lnk = (const H5O_link_t *)_mesg;  /* Pointer to link */
    H5G_compact_ud2_t *udata = (H5G_compact_ud2_t *)_udata;     /* 'User data' passed in */
    herr_t ret_value = H5O_ITER_CONT;           /* Return value */

    FUNC_ENTER_NOAPI_NOINIT(H5G_compact_remove_cb)

    /* check arguments */
    HDassert(lnk);
    HDassert(udata);

    /* If we've found the right link, get the object type */
    if(HDstrcmp(lnk->name, udata->name) == 0) {
        switch(lnk->type)
        {
            case H5L_TYPE_HARD:
                {
                    H5O_loc_t tmp_oloc;             /* Temporary object location */

                    /* Build temporary object location */
                    tmp_oloc.file = udata->file;
                    tmp_oloc.addr = lnk->u.hard.addr;

                    /* Get the type of the object */
                    /* Note: no way to check for error :-( */
                    *(udata->obj_type) = H5O_obj_type(&tmp_oloc, udata->dxpl_id);
                }
                break;

            case H5L_TYPE_SOFT:
                *(udata->obj_type) = H5G_LINK;
                break;

            default:  /* User-defined link */
                if(lnk->type < H5L_TYPE_UD_MIN)
                   HGOTO_ERROR(H5E_SYM, H5E_BADVALUE, FAIL, "unknown link type")

                *(udata->obj_type) = H5G_UDLINK;
        }
        /* Stop the iteration, we found the correct link */
        HGOTO_DONE(H5O_ITER_STOP)
    } /* end if */

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_remove_cb() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_remove
 *
 * Purpose:	Remove NAME from links.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *              Monday, September 19, 2005
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5G_compact_remove(const H5O_loc_t *oloc, const char *name, H5G_obj_t *obj_type,
    hid_t dxpl_id)
{
    H5G_compact_ud2_t udata;               /* Data to pass through OH iteration */
    herr_t ret_value = SUCCEED;         /* Return value */

    FUNC_ENTER_NOAPI(H5G_compact_remove, FAIL)

    HDassert(oloc && oloc->file);
    HDassert(name && *name);

    /* Initialize data to pass through object header iteration */
    udata.name = name;
    udata.file = oloc->file;
    udata.dxpl_id = dxpl_id;
    udata.obj_type = obj_type;

    /* Iterate over the link messages to delete the right one */
    if(H5O_remove_op(oloc, H5O_LINK_ID, H5O_FIRST, H5G_compact_remove_cb, &udata, TRUE, dxpl_id) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_CANTDELETE, FAIL, "unable to delete link message")

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_remove() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_iterate
 *
 * Purpose:	Iterate over the links in a group
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *              Monday, October  3, 2005
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5G_compact_iterate(H5O_loc_t *oloc, hid_t dxpl_id, const H5O_linfo_t *linfo, 
    H5_iter_order_t order, hid_t gid, hbool_t lib_internal, int skip,
    int *last_obj, H5G_link_iterate_t op, void *op_data)
{
    H5G_link_table_t    ltable = {0, NULL};     /* Link table */
    size_t              u;                      /* Local index variable */
    herr_t		ret_value;

    FUNC_ENTER_NOAPI(H5G_compact_iterate, FAIL)

    /* Sanity check */
    HDassert(oloc);
    HDassert(lib_internal || H5I_GROUP == H5I_get_type(gid));
    HDassert(op.lib_op);

    /* Build table of all link messages */
    if(H5G_compact_build_table(oloc, dxpl_id, linfo, H5L_INDEX_NAME, order, &ltable) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_CANTINIT, FAIL, "can't create link message table")

    /* Iterate over link messages */
    for(u = 0, ret_value = H5B_ITER_CONT; u < ltable.nlinks && !ret_value; u++) {
        if(skip > 0)
            --skip;
        else {
            /* Check for internal callback with link info */
            if(lib_internal)
                ret_value = (op.lib_op)(&(ltable.lnks[u]), op_data);
            else
                ret_value = (op.app_op)(gid, ltable.lnks[u].name, op_data);
        } /* end else */

        /* Increment the number of entries passed through */
        /* (whether we skipped them or not) */
        (*last_obj)++;
    } /* end for */

    /* Check for callback failure and pass along return value */
    if(ret_value < 0)
        HERROR(H5E_SYM, H5E_CANTNEXT, "iteration operator failed");

done:
    /* Release link table */
    if(ltable.lnks)
        /* Free link table information */
        if(H5G_link_release_table(&ltable) < 0)
            HDONE_ERROR(H5E_SYM, H5E_CANTFREE, FAIL, "unable to release link table")

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_iterate() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_lookup_cb
 *
 * Purpose:	Callback routine for searching 'link' messages for a particular
 *              name & gettting object location for it
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *		koziol@ncsa.uiuc.edu
 *		Sep 20 2005
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5G_compact_lookup_cb(const void *_mesg, unsigned UNUSED idx, void *_udata)
{
    const H5O_link_t *lnk = (const H5O_link_t *)_mesg;  /* Pointer to link */
    H5G_compact_ud4_t *udata = (H5G_compact_ud4_t *)_udata;     /* 'User data' passed in */
    herr_t ret_value = H5O_ITER_CONT;           /* Return value */

    FUNC_ENTER_NOAPI_NOINIT(H5G_compact_lookup_cb)

    /* check arguments */
    HDassert(lnk);
    HDassert(udata);

    /* Check for name to get information */
    if(HDstrcmp(lnk->name, udata->name) == 0) {
        if(udata->lnk) {
            /* Copy link information */
            if(NULL == H5O_copy(H5O_LINK_ID, lnk, udata->lnk))
                HGOTO_ERROR(H5E_SYM, H5E_CANTCOPY, H5O_ITER_ERROR, "can't copy link message")
        } /* end if */

        /* Indicate that the correct link was found */
        udata->found = TRUE;

        /* Stop iteration now */
        HGOTO_DONE(H5O_ITER_STOP)
    } /* end if */

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_lookup_cb() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_lookup
 *
 * Purpose:	Look up an object relative to a group, using link messages.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *		koziol@ncsa.uiuc.edu
 *		Sep 20 2005
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5G_compact_lookup(H5O_loc_t *oloc, const char *name, H5O_link_t *lnk,
    hid_t dxpl_id)
{
    H5G_compact_ud4_t udata;               /* User data for iteration callback */
    herr_t     ret_value = SUCCEED;     /* Return value */

    FUNC_ENTER_NOAPI(H5G_compact_lookup, FAIL)

    /* check arguments */
    HDassert(lnk && oloc->file);
    HDassert(name && *name);

    /* Set up user data for iteration */
    udata.name = name;
    udata.lnk = lnk;
    udata.found = FALSE;

    /* Iterate through the link messages, adding them to the table */
    if(H5O_iterate(oloc, H5O_LINK_ID, H5G_compact_lookup_cb, &udata, dxpl_id) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_NOTFOUND, FAIL, "error iterating over link messages")

    /* Check if we found the link we were looking for */
    if(!udata.found)
        HGOTO_ERROR(H5E_SYM, H5E_NOTFOUND, FAIL, "object not found")

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_lookup() */


/*-------------------------------------------------------------------------
 * Function:	H5G_compact_lookup_by_idx
 *
 * Purpose:	Look up an object in a group using link messages,
 *              according to the order of an index
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *		koziol@hdfgroup.org
 *		Nov  6 2006
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5G_compact_lookup_by_idx(H5O_loc_t *oloc, hid_t dxpl_id, const H5O_linfo_t *linfo,
    H5L_index_t idx_type, H5_iter_order_t order, hsize_t n, H5O_link_t *lnk)
{
    H5G_link_table_t    ltable = {0, NULL};     /* Link table */
    herr_t     ret_value = SUCCEED;     /* Return value */

    FUNC_ENTER_NOAPI(H5G_compact_lookup_by_idx, FAIL)

    /* check arguments */
    HDassert(oloc && oloc->file);
    HDassert(linfo);
    HDassert(lnk);

    /* Build table of all link messages, sorted according to desired order */
    if(H5G_compact_build_table(oloc, dxpl_id, linfo, idx_type, order, &ltable) < 0)
        HGOTO_ERROR(H5E_SYM, H5E_CANTINIT, FAIL, "can't create link message table")

    /* Check for going out of bounds */
    if(n >= ltable.nlinks)
	HGOTO_ERROR(H5E_ARGS, H5E_BADRANGE, FAIL, "index out of bound")

    /* Copy link information */
    if(NULL == H5O_copy(H5O_LINK_ID, &ltable.lnks[n], lnk))
        HGOTO_ERROR(H5E_SYM, H5E_CANTCOPY, H5O_ITER_ERROR, "can't copy link message")

done:
    /* Release link table */
    if(ltable.lnks)
        /* Free link table information */
        if(H5G_link_release_table(&ltable) < 0)
            HDONE_ERROR(H5E_SYM, H5E_CANTFREE, FAIL, "unable to release link table")

    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5G_compact_lookup_by_idx() */
