/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Copyright by The HDF Group.                                               *
 * Copyright by the Board of Trustees of the University of Illinois.         *
 * All rights reserved.                                                      *
 *                                                                           *
 * This file is part of HDF5.  The full HDF5 copyright notice, including     *
 * terms governing use, modification, and redistribution, is contained in    *
 * the files COPYING and Copyright.html.  COPYING can be found at the root   *
 * of the source code distribution tree; Copyright.html can be found at the  *
 * root level of an installed copy of the electronic HDF5 document set and   *
 * is linked from the top-level documents page.  It can also be found at     *
 * http://hdfgroup.org/HDF5/doc/Copyright.html.  If you do not have          *
 * access to either file, you may request a copy from help@hdfgroup.org.     *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*-------------------------------------------------------------------------
 *
 * Created:	H5Eint.c
 *		April 11 2007
 *		Quincey Koziol <koziol@hdfgroup.org>
 *
 * Purpose:	General use, "internal" routines for error handling.
 *
 *-------------------------------------------------------------------------
 */

/****************/
/* Module Setup */
/****************/

#define H5E_PACKAGE		/*suppress error about including H5Epkg   */

/* Interface initialization */
#define H5_INTERFACE_INIT_FUNC	H5E_init_int_interface


/***********/
/* Headers */
/***********/
#include "H5private.h"		/* Generic Functions			*/
#include "H5Epkg.h"		/* Error handling		  	*/
#include "H5Iprivate.h"		/* IDs                                  */
#include "H5MMprivate.h"	/* Memory management			*/


/****************/
/* Local Macros */
/****************/


/******************/
/* Local Typedefs */
/******************/


/********************/
/* Package Typedefs */
/********************/


/********************/
/* Local Prototypes */
/********************/
static herr_t H5E_walk_cb(unsigned n, const H5E_error_t *err_desc,
    void *client_data);
static herr_t H5E_walk2_cb(unsigned n, const H5E_error2_t *err_desc,
    void *client_data);
static herr_t  H5E_clear_entries(H5E_t *estack, size_t nentries);


/*********************/
/* Package Variables */
/*********************/

#ifndef H5_HAVE_THREADSAFE
/*
 * The current error stack.
 */
H5E_t H5E_stack_g[1];
#endif /* H5_HAVE_THREADSAFE */


/*****************************/
/* Library Private Variables */
/*****************************/

/* HDF5 error class ID */
hid_t H5E_ERR_CLS_g = FAIL;

/*
 * Predefined errors. These are initialized at runtime in H5E_init_interface()
 * in this source file.
 */
/* Include the automatically generated error code definitions */
#include "H5Edefin.h"


/*******************/
/* Local Variables */
/*******************/

#ifdef H5_HAVE_PARALLEL
/*
 * variables used for MPI error reporting
 */
char	H5E_mpi_error_str[MPI_MAX_ERROR_STRING];
int	H5E_mpi_error_str_len;
#endif



/*--------------------------------------------------------------------------
NAME
   H5E_init_int_interface -- Initialize interface-specific information
USAGE
    herr_t H5E_init_int_interface()
RETURNS
    Non-negative on success/Negative on failure
DESCRIPTION
    Initializes any interface-specific data or routines.  (Just calls
    H5E_init() currently).

--------------------------------------------------------------------------*/
static herr_t
H5E_init_int_interface(void)
{
    FUNC_ENTER_NOAPI_NOINIT_NOFUNC(H5E_init_int_interface)

    FUNC_LEAVE_NOAPI(H5E_init())
} /* H5E_init_int_interface() */


/*-------------------------------------------------------------------------
 * Function:	H5E_get_msg
 *
 * Purpose:	Private function to retrieve an error message.
 *
 * Return:      Non-negative for name length if succeeds(zero means no name);
 *              otherwise returns negative value.
 *
 * Programmer:	Raymond Lu
 *              Friday, July 14, 2003
 *
 *-------------------------------------------------------------------------
 */
ssize_t
H5E_get_msg(const H5E_msg_t *msg, H5E_type_t *type, char *msg_str, size_t size)
{
    ssize_t       len;          /* Length of error message */

    FUNC_ENTER_NOAPI_NOINIT_NOFUNC(H5E_get_msg)

    /* Check arguments */
    HDassert(msg);

    /* Get the length of the message string */
    len = (ssize_t)HDstrlen(msg->msg);

    /* Copy the message into the user's buffer, if given */
    if(msg_str) {
       HDstrncpy(msg_str, msg->msg, MIN((size_t)(len+1), size));
       if((size_t)len >= size)
          msg_str[size - 1] = '\0';
    } /* end if */

    /* Give the message type, if asked */
    if(type)
        *type = msg->type;

    /* Set the return value to the full length of the message */
    FUNC_LEAVE_NOAPI(len)
} /* end H5E_get_msg() */


/*-------------------------------------------------------------------------
 * Function:	H5E_walk_cb
 *
 * Purpose:	This function is for backward compatibility.
 *              This is a default error stack traversal callback function
 *		that prints error messages to the specified output stream.
 *		This function is for backward compatibility with v1.6.
 *		It is not meant to be called directly but rather as an
 *		argument to the H5Ewalk() function.  This function is called
 *		also by H5Eprint().  Application writers are encouraged to
 *		use this function as a model for their own error stack
 *		walking functions.
 *
 *		N is a counter for how many times this function has been
 *		called for this particular traversal of the stack.  It always
 *		begins at zero for the first error on the stack (either the
 *		top or bottom error, or even both, depending on the traversal
 *		direction and the size of the stack).
 *
 *		ERR_DESC is an error description.  It contains all the
 *		information about a particular error.
 *
 *		CLIENT_DATA is the same pointer that was passed as the
 *		CLIENT_DATA argument of H5Ewalk().  It is expected to be a
 *		file pointer (or stderr if null).
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:  Raymond Lu
 *		Thursday, May 11, 2006
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5E_walk_cb(unsigned n, const H5E_error_t *err_desc, void *client_data)
{
    H5E_print_t         *eprint  = (H5E_print_t *)client_data;
    FILE		*stream;        /* I/O stream to print output to */
    H5E_cls_t           *cls_ptr;       /* Pointer to error class */
    H5E_msg_t           *maj_ptr;       /* Pointer to major error info */
    H5E_msg_t           *min_ptr;       /* Pointer to minor error info */
    const char		*maj_str = "No major description";      /* Major error description */
    const char		*min_str = "No minor description";      /* Minor error description */
    unsigned            have_desc = 1;  /* Flag to indicate whether the error has a "real" description */

    FUNC_ENTER_NOAPI_NOINIT_NOFUNC(H5E_walk_cb)

    /* Check arguments */
    HDassert(err_desc);

    /* If no client data was passed, output to stderr */
    if(!client_data)
        stream = stderr;
    else
        stream = eprint->stream;

    /* Get descriptions for the major and minor error numbers */
    maj_ptr = H5I_object_verify(err_desc->maj_num, H5I_ERROR_MSG);
    min_ptr = H5I_object_verify(err_desc->min_num, H5I_ERROR_MSG);
    HDassert(maj_ptr && min_ptr);
    if(maj_ptr->msg)
        maj_str = maj_ptr->msg;
    if(min_ptr->msg)
        min_str = min_ptr->msg;

    /* Get error class info */
    cls_ptr = maj_ptr->cls;

    /* Print error class header if new class */
    if(eprint->cls.lib_name == NULL || HDstrcmp(cls_ptr->lib_name, eprint->cls.lib_name)) {
        /* update to the new class information */
        if(cls_ptr->cls_name)
            eprint->cls.cls_name = cls_ptr->cls_name;
        if(cls_ptr->lib_name)
            eprint->cls.lib_name = cls_ptr->lib_name;
        if(cls_ptr->lib_vers)
            eprint->cls.lib_vers = cls_ptr->lib_vers;

        fprintf(stream, "%s-DIAG: Error detected in %s (%s) ", cls_ptr->cls_name, cls_ptr->lib_name, cls_ptr->lib_vers);

        /* try show the process or thread id in multiple processes cases*/
#ifdef H5_HAVE_PARALLEL
        {
            int mpi_rank, mpi_initialized;

	    MPI_Initialized(&mpi_initialized);
	    if(mpi_initialized) {
	        MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
	        fprintf (stream, "MPI-process %d", mpi_rank);
	    } /* end if */
            else
	        fprintf(stream, "thread 0");
        } /* end block */
#elif defined(H5_HAVE_THREADSAFE)
#ifdef WIN32
        fprintf(stream, "some thread: no way to know the thread number from pthread on windows");
#else
        fprintf(stream, "thread %lu", (unsigned long)pthread_self());
#endif
#else
        fprintf(stream, "thread 0");
#endif
        fprintf(stream, ":\n");
    } /* end if */

    /* Check for "real" error description - used to format output more nicely */
    if(err_desc->desc == NULL || HDstrlen(err_desc->desc) == 0)
        have_desc=0;

    /* Print error message */
    fprintf(stream, "%*s#%03u: %s line %u in %s()%s%s\n",
	     H5E_INDENT, "", n, err_desc->file_name, err_desc->line,
	     err_desc->func_name, (have_desc ? ": " : ""),
             (have_desc ? err_desc->desc : ""));
    fprintf(stream, "%*smajor: %s\n", (H5E_INDENT * 2), "", maj_str);
    fprintf(stream, "%*sminor: %s\n", (H5E_INDENT * 2), "", min_str);

    FUNC_LEAVE_NOAPI(SUCCEED)
} /* end H5E_walk_cb() */


/*-------------------------------------------------------------------------
 * Function:	H5E_walk2_cb
 *
 * Purpose:	This is a default error stack traversal callback function
 *		that prints error messages to the specified output stream.
 *		It is not meant to be called directly but rather as an
 *		argument to the H5Ewalk2() function.  This function is
 *		called also by H5Eprint2().  Application writers are
 *		encouraged to use this function as a model for their own
 *		error stack walking functions.
 *
 *		N is a counter for how many times this function has been
 *		called for this particular traversal of the stack.  It always
 *		begins at zero for the first error on the stack (either the
 *		top or bottom error, or even both, depending on the traversal
 *		direction and the size of the stack).
 *
 *		ERR_DESC is an error description.  It contains all the
 *		information about a particular error.
 *
 *		CLIENT_DATA is the same pointer that was passed as the
 *		CLIENT_DATA argument of H5Ewalk().  It is expected to be a
 *		file pointer (or stderr if null).
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Robb Matzke
 *		Friday, December 12, 1997
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5E_walk2_cb(unsigned n, const H5E_error2_t *err_desc, void *client_data)
{
    H5E_print_t         *eprint  = (H5E_print_t *)client_data;
    FILE		*stream;        /* I/O stream to print output to */
    H5E_cls_t           *cls_ptr;       /* Pointer to error class */
    H5E_msg_t           *maj_ptr;       /* Pointer to major error info */
    H5E_msg_t           *min_ptr;       /* Pointer to minor error info */
    const char		*maj_str = "No major description";      /* Major error description */
    const char		*min_str = "No minor description";      /* Minor error description */
    unsigned            have_desc = 1;  /* Flag to indicate whether the error has a "real" description */

    FUNC_ENTER_NOAPI_NOINIT_NOFUNC(H5E_walk2_cb)

    /* Check arguments */
    HDassert(err_desc);

    /* If no client data was passed, output to stderr */
    if(!client_data)
        stream = stderr;
    else
        stream = eprint->stream;

    /* Get descriptions for the major and minor error numbers */
    maj_ptr = H5I_object_verify(err_desc->maj_num, H5I_ERROR_MSG);
    min_ptr = H5I_object_verify(err_desc->min_num, H5I_ERROR_MSG);
    HDassert(maj_ptr && min_ptr);
    if(maj_ptr->msg)
        maj_str = maj_ptr->msg;
    if(min_ptr->msg)
        min_str = min_ptr->msg;

    /* Get error class info */
    cls_ptr = maj_ptr->cls;

    /* Print error class header if new class */
    if(eprint->cls.lib_name == NULL || HDstrcmp(cls_ptr->lib_name, eprint->cls.lib_name)) {
        /* update to the new class information */
        if(cls_ptr->cls_name)
            eprint->cls.cls_name = cls_ptr->cls_name;
        if(cls_ptr->lib_name)
            eprint->cls.lib_name = cls_ptr->lib_name;
        if(cls_ptr->lib_vers)
            eprint->cls.lib_vers = cls_ptr->lib_vers;

        fprintf(stream, "%s-DIAG: Error detected in %s (%s) ", cls_ptr->cls_name, cls_ptr->lib_name, cls_ptr->lib_vers);

        /* try show the process or thread id in multiple processes cases*/
#ifdef H5_HAVE_PARALLEL
        {
            int mpi_rank, mpi_initialized;

	    MPI_Initialized(&mpi_initialized);
	    if(mpi_initialized) {
	        MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
	        fprintf(stream, "MPI-process %d", mpi_rank);
	    } /* end if */
            else
	        fprintf(stream, "thread 0");
        } /* end block */
#elif defined(H5_HAVE_THREADSAFE)
#ifdef WIN32
        fprintf(stream, "some thread: no way to know the thread number from pthread on windows");
#else
        fprintf(stream, "thread %lu", (unsigned long)pthread_self());
#endif
#else
        fprintf(stream, "thread 0");
#endif
        fprintf(stream, ":\n");
    } /* end if */

    /* Check for "real" error description - used to format output more nicely */
    if(err_desc->desc == NULL || HDstrlen(err_desc->desc) == 0)
        have_desc = 0;

    /* Print error message */
    fprintf(stream, "%*s#%03u: %s line %u in %s()%s%s\n",
	     H5E_INDENT, "", n, err_desc->file_name, err_desc->line,
	     err_desc->func_name, (have_desc ? ": " : ""),
             (have_desc ? err_desc->desc : ""));
    fprintf(stream, "%*smajor: %s\n", (H5E_INDENT * 2), "", maj_str);
    fprintf(stream, "%*sminor: %s\n", (H5E_INDENT * 2), "", min_str);

    FUNC_LEAVE_NOAPI(SUCCEED)
} /* end H5E_walk2_cb() */


/*-------------------------------------------------------------------------
 * Function:	H5E_print2
 *
 * Purpose:	Private function to print the error stack in some default
 *              way.  This is just a convenience function for H5Ewalk() and
 *              H5Ewalk2() with a function that prints error messages.
 *              Users are encouraged to write there own more specific error
 *              handlers.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Robb Matzke
 *              Friday, February 27, 1998
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5E_print2(const H5E_t *estack, FILE *stream, hbool_t bk_compatible)
{
    H5E_print_t eprint;         /* Callback information to pass to H5E_walk2() */
    herr_t ret_value = SUCCEED;

    /* Don't clear the error stack! :-) */
    FUNC_ENTER_NOAPI_NOINIT(H5E_print2)

    /* Sanity check */
    HDassert(estack);

    /* If no stream was given, use stderr */
    if(!stream)
        eprint.stream = stderr;
    else
        eprint.stream = stream;

    /* Reset the original error class information */
    HDmemset(&eprint.cls, 0, sizeof(H5E_cls_t));

    /* Walk the error stack */
    if(bk_compatible) {
        if(H5E_walk2(estack, H5E_WALK_DOWNWARD, H5E_walk_cb, NULL, TRUE, (void*)&eprint) < 0)
            HGOTO_ERROR(H5E_ERROR, H5E_CANTLIST, FAIL, "can't walk error stack")
    } /* end if */
    else {
        if(H5E_walk2(estack, H5E_WALK_DOWNWARD, NULL, H5E_walk2_cb, FALSE, (void*)&eprint) < 0)
            HGOTO_ERROR(H5E_ERROR, H5E_CANTLIST, FAIL, "can't walk error stack")
    } /* end else */

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5E_print2() */


/*-------------------------------------------------------------------------
 * Function:	H5E_walk2
 *
 * Purpose:	Private function for H5Ewalk.
 *              Walks the error stack, calling the specified function for
 *		each error on the stack.  The DIRECTION argument determines
 *		whether the stack is walked from the inside out or the
 *		outside in.  The value H5E_WALK_UPWARD means begin with the
 *		most specific error and end at the API; H5E_WALK_DOWNWARD
 *		means to start at the API and end at the inner-most function
 *		where the error was first detected.
 *
 *		The function pointed to by STACK_FUNC will be called for
 *		each error record in the error stack. It's arguments will
 *		include an index number (beginning at zero regardless of
 *		stack traversal	direction), an error stack entry, and the
 *		CLIENT_DATA pointer passed to H5E_print2.
 *
 *		The function FUNC is also provided for backward compatibility.
 *		When BK_COMPATIBLE is set to be TRUE, FUNC is used to be
 *		compatible with older library.  If BK_COMPATIBLE is FALSE,
 *		STACK_FUNC is used.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Robb Matzke
 *		Friday, December 12, 1997
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5E_walk2(const H5E_t *estack, H5E_direction_t direction, H5E_walk_t func, H5E_walk2_t stack_func,
        hbool_t bk_compatible, void *client_data)
{
    int		i;              /* Local index variable */
    herr_t	status;         /* Status from callback function */
    herr_t ret_value = SUCCEED;   /* Return value */

    FUNC_ENTER_NOAPI_NOINIT(H5E_walk2)

    /* Sanity check */
    HDassert(estack);

    /* check args, but rather than failing use some default value */
    if(direction != H5E_WALK_UPWARD && direction != H5E_WALK_DOWNWARD)
	direction = H5E_WALK_UPWARD;

    /* Walk the stack if a callback function was given */
    if(bk_compatible && func) {
        H5E_error_t old_err;

        status = SUCCEED;
        if(H5E_WALK_UPWARD == direction) {
            for(i = 0; i < (int)estack->nused && status >= 0; i++) {
                /* Point to each error record on the stack and pass it to callback function.*/
                old_err.maj_num = estack->slot[i].maj_num;
                old_err.min_num = estack->slot[i].min_num;
                old_err.func_name = estack->slot[i].func_name;
                old_err.file_name = estack->slot[i].file_name;
                old_err.desc = estack->slot[i].desc;
                old_err.line = estack->slot[i].line;

                status = (func)((unsigned)i, &old_err, client_data);
            } /* end for */
        } /* end if */
        else {
            H5_CHECK_OVERFLOW(estack->nused - 1, size_t, int);
            for(i = (int)(estack->nused - 1); i >= 0 && status >= 0; i--) {
                /* Point to each error record on the stack and pass it to callback function.*/
                old_err.maj_num = estack->slot[i].maj_num;
                old_err.min_num = estack->slot[i].min_num;
                old_err.func_name = estack->slot[i].func_name;
                old_err.file_name = estack->slot[i].file_name;
                old_err.desc = estack->slot[i].desc;
                old_err.line = estack->slot[i].line;

                status = (func)((unsigned)(estack->nused - (size_t)(i + 1)), &old_err, client_data);
            } /* end for */
        } /* end else */

        if(status < 0)
            HGOTO_ERROR(H5E_ERROR, H5E_CANTLIST, FAIL, "can't walk error stack")
    } /* end if */
    else if(!bk_compatible && stack_func) {
        status = SUCCEED;
        if(H5E_WALK_UPWARD == direction) {
            for(i = 0; i < (int)estack->nused && status >= 0; i++)
                status = (stack_func)((unsigned)i, estack->slot + i, client_data);
        } /* end if */
        else {
            H5_CHECK_OVERFLOW(estack->nused - 1, size_t, int);
            for(i = (int)(estack->nused - 1); i >= 0 && status >= 0; i--)
                status = (stack_func)((unsigned)(estack->nused-(size_t)(i + 1)), estack->slot + i, client_data);
        } /* end else */

        if(status < 0)
            HGOTO_ERROR(H5E_ERROR, H5E_CANTLIST, FAIL, "can't walk error stack")
    } /* end if */

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5E_walk2() */


/*-------------------------------------------------------------------------
 * Function:	H5E_get_auto2
 *
 * Purpose:	Private function to return the current settings for the
 *              automatic error stack traversal function and its data
 *              for specific error stack. Either (or both) arguments may
 *              be null in which case the value is not returned.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Raymond Lu
 *              July 18, 2003
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5E_get_auto2(const H5E_t *estack, hbool_t new_api, H5E_auto_op_t *func, void **client_data)
{
    FUNC_ENTER_NOAPI_NOINIT_NOFUNC(H5E_get_auto2)

    HDassert(estack);

    /* Retrieve the requested information */
    if(func) {
        if(new_api)
            func->efunc2 = estack->u.func2;
        else
            func->efunc = estack->u.func;
    } /* end if */
    if(client_data)
        *client_data = estack->auto_data;

    FUNC_LEAVE_NOAPI(SUCCEED)
} /* end H5E_get_auto2() */


/*-------------------------------------------------------------------------
 * Function:	H5E_set_auto2
 *
 * Purpose:	Private function to turn on or off automatic printing of
 *              errors for certain error stack.  When turned on (non-null
 *              FUNC pointer) any API function which returns an error
 *              indication will first call FUNC passing it CLIENT_DATA
 *              as an argument.
 *
 *		The default values before this function is called are
 *		H5Eprint() with client data being the standard error stream,
 *		stderr.
 *
 *		Automatic stack traversal is always in the H5E_WALK_DOWNWARD
 *		direction.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Robb Matzke
 *              Friday, February 27, 1998
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5E_set_auto2(H5E_t *estack, hbool_t new_api, H5E_auto_op_t *func, void *client_data)
{
    FUNC_ENTER_NOAPI_NOINIT_NOFUNC(H5E_set_auto2)

    HDassert(estack);

    /* Set the automatic error reporting info */
    estack->new_api = new_api;
    if(new_api)
        estack->u.func2 = func->efunc2;
    else
        estack->u.func = func->efunc;
    estack->auto_data = client_data;

    FUNC_LEAVE_NOAPI(SUCCEED)
} /* end H5E_set_auto2() */


/*-------------------------------------------------------------------------
 * Function:	H5E_push_stack
 *
 * Purpose:	Pushes a new error record onto error stack for the current
 *		thread.  The error has major and minor IDs MAJ_ID and
 *		MIN_ID, the name of a function where the error was detected,
 *		the name of the file where the error was detected, the
 *		line within that file, and an error description string.  The
 *		function name, file name, and error description strings must
 *		be statically allocated (the FUNC_ENTER() macro takes care of
 *		the function name and file name automatically, but the
 *		programmer is responsible for the description string).
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Robb Matzke
 *		Friday, December 12, 1997
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5E_push_stack(H5E_t *estack, const char *file, const char *func, unsigned line,
        hid_t cls_id, hid_t maj_id, hid_t min_id, const char *desc)
{
    herr_t	ret_value = SUCCEED;      /* Return value */

    /*
     * WARNING: We cannot call HERROR() from within this function or else we
     *		could enter infinite recursion.  Furthermore, we also cannot
     *		call any other HDF5 macro or function which might call
     *		HERROR().  HERROR() is called by HRETURN_ERROR() which could
     *		be called by FUNC_ENTER().
     */
    FUNC_ENTER_NOAPI_NOINIT_NOFUNC(H5E_push_stack)

    /* Sanity check */
    HDassert(cls_id > 0);
    HDassert(maj_id > 0);
    HDassert(min_id > 0);

    /* Check for 'default' error stack */
    if(estack == NULL)
    	if(NULL == (estack = H5E_get_my_stack())) /*lint !e506 !e774 Make lint 'constant value Boolean' in non-threaded case */
            HGOTO_DONE(FAIL)

    /*
     * Don't fail if arguments are bad.  Instead, substitute some default
     * value.
     */
    if(!func)
        func = "Unknown_Function";
    if(!file)
        file = "Unknown_File";
    if(!desc)
        desc = "No description given";

    /*
     * Push the error if there's room.  Otherwise just forget it.
     */
    HDassert(estack);

    if(estack->nused < H5E_NSLOTS) {
        /* Increment the IDs to indicate that they are used in this stack */
        if(H5I_inc_ref(cls_id) < 0)
            HGOTO_DONE(FAIL)
	estack->slot[estack->nused].cls_id = cls_id;
        if(H5I_inc_ref(maj_id) < 0)
            HGOTO_DONE(FAIL)
	estack->slot[estack->nused].maj_num = maj_id;
        if(H5I_inc_ref(min_id) < 0)
            HGOTO_DONE(FAIL)
	estack->slot[estack->nused].min_num = min_id;
	if(NULL == (estack->slot[estack->nused].func_name = H5MM_xstrdup(func)))
            HGOTO_DONE(FAIL)
	if(NULL == (estack->slot[estack->nused].file_name = H5MM_xstrdup(file)))
            HGOTO_DONE(FAIL)
	estack->slot[estack->nused].line = line;
	if(NULL == (estack->slot[estack->nused].desc = H5MM_xstrdup(desc)))
            HGOTO_DONE(FAIL)
	estack->nused++;
    } /* end if */

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5E_push_stack() */


/*-------------------------------------------------------------------------
 * Function:	H5E_clear_entries
 *
 * Purpose:	Private function to clear the error stack entries for the
 *              specified error stack.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Quincey Koziol
 *              Wednesday, August 6, 2003
 *
 *-------------------------------------------------------------------------
 */
static herr_t
H5E_clear_entries(H5E_t *estack, size_t nentries)
{
    H5E_error2_t *error;        /* Pointer to error stack entry to clear */
    unsigned u;                 /* Local index variable */
    herr_t ret_value=SUCCEED;   /* Return value */

    FUNC_ENTER_NOAPI_NOINIT(H5E_clear_entries)

    /* Sanity check */
    HDassert(estack);
    HDassert(estack->nused >= nentries);

    /* Empty the error stack from the top down */
    for(u = 0; nentries > 0; nentries--, u++) {
        error = &(estack->slot[estack->nused - (u + 1)]);

        /* Decrement the IDs to indicate that they are no longer used by this stack */
        /* (In reverse order that they were incremented, so that reference counts work well) */
        if(H5I_dec_ref(error->min_num) < 0)
            HGOTO_ERROR(H5E_ERROR, H5E_CANTDEC, FAIL, "unable to decrement ref count on error message")
        if(H5I_dec_ref(error->maj_num) < 0)
            HGOTO_ERROR(H5E_ERROR, H5E_CANTDEC, FAIL, "unable to decrement ref count on error message")
        if(H5I_dec_ref(error->cls_id) < 0)
            HGOTO_ERROR(H5E_ERROR, H5E_CANTDEC, FAIL, "unable to decrement ref count on error class")

        /* Release strings */
        if(error->func_name)
            H5MM_xfree((void *)error->func_name);        /* Casting away const OK - QAK */
        if(error->file_name)
            H5MM_xfree((void *)error->file_name);        /* Casting away const OK - QAK */
        if(error->desc)
            H5MM_xfree((void *)error->desc);     /* Casting away const OK - QAK */
    } /* end for */

    /* Decrement number of errors on stack */
    estack->nused -= u;

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5E_clear_entries() */


/*-------------------------------------------------------------------------
 * Function:	H5E_clear_stack
 *
 * Purpose:	Private function to clear the error stack for the
 *              specified error stack.
 *
 * Return:	Non-negative on success/Negative on failure
 *
 * Programmer:	Raymond Lu
 *              Wednesday, July 16, 2003
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5E_clear_stack(H5E_t *estack)
{
    herr_t ret_value = SUCCEED;   /* Return value */

    FUNC_ENTER_NOAPI(H5E_clear_stack, FAIL)

    /* Check for 'default' error stack */
    if(estack == NULL)
    	if(NULL == (estack = H5E_get_my_stack())) /*lint !e506 !e774 Make lint 'constant value Boolean' in non-threaded case */
            HGOTO_ERROR(H5E_ERROR, H5E_CANTGET, FAIL, "can't get current error stack")

    /* Empty the error stack */
    HDassert(estack);
    if(estack->nused)
        if(H5E_clear_entries(estack, estack->nused) < 0)
            HGOTO_ERROR(H5E_ERROR, H5E_CANTSET, FAIL, "can't clear error stack")

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5E_clear_stack() */


/*-------------------------------------------------------------------------
 * Function:	H5E_pop
 *
 * Purpose:	Private function to delete some error messages from the top
 *              of error stack.
 *
 * Return:	Non-negative value on success/Negative on failure
 *
 * Programmer:	Raymond Lu
 *              Friday, July 16, 2003
 *
 *-------------------------------------------------------------------------
 */
herr_t
H5E_pop(H5E_t *estack, size_t count)
{
    herr_t      ret_value = SUCCEED;   /* Return value */

    FUNC_ENTER_NOAPI_NOINIT(H5E_pop)

    /* Sanity check */
    HDassert(estack);
    HDassert(estack->nused >= count);

    /* Remove the entries from the error stack */
    if(H5E_clear_entries(estack, count) < 0)
        HGOTO_ERROR(H5E_ERROR, H5E_CANTRELEASE, FAIL, "can't remove errors from stack")

done:
    FUNC_LEAVE_NOAPI(ret_value)
} /* end H5E_pop() */
