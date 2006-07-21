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

/*
 * Programmer:  Quincey Koziol <koziol@ncsa.uiuc.edu>
 *              Friday, June 30, 2006
 *
 *  This program creates an object with fragmented object header messages
 *  that will be merged when the object is read from the file.  This program
 *  needs to be compiled against the 1.6.5 or earlier version of the library
 *  in order to generate the file as desired.
 */

#include <assert.h>
#include <stdio.h>
#include "hdf5.h"

#define FILENAME        "mergemsg.h5"
#define GROUP1          "grp1"
#define GROUP2          "grp2"
#define GROUP3          "grp3"
#define ATTR1           "__111111111111__"
#define ATTR1_LEN       11
#define ATTR2           "__222222222__"
#define ATTR2_LEN       11
#define ATTR3           "__333333333__"
#define ATTR3_LEN       1

int main()
{
    hid_t fid;          /* File ID */
    hid_t gid, gid2, gid3;      /* Group IDs */
    hid_t aid;          /* Attribute ID */
    hid_t sid;          /* Dataspace ID */
    hid_t tid;          /* Datatype ID */
    herr_t ret;         /* Generic return value */

    /* Create file */
    fid = H5Fcreate(FILENAME, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    assert(fid > 0);

    /* Create first group */
    gid = H5Gcreate(fid, GROUP1, (size_t)0);
    assert(gid > 0);

    /* Close first group */
    ret = H5Gclose(gid);
    assert(ret >= 0);

    /* Create second group */
    gid2 = H5Gcreate(fid, GROUP2, (size_t)0);
    assert(gid2 > 0);

    /* Close second group */
    ret = H5Gclose(gid2);
    assert(ret >= 0);

    /* Close file */
    ret = H5Fclose(fid);
    assert(ret >= 0);


    /* Re-open file */
    fid = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    assert(fid > 0);

    /* Re-open first group */
    gid = H5Gopen(fid, GROUP1);
    assert(gid > 0);

    /* Create dataspace for attribute */
    sid = H5Screate(H5S_SCALAR);
    assert(sid > 0);

    /* Create dataype for attribute */
    tid = H5Tcopy(H5T_C_S1);
    assert(tid > 0);
    ret = H5Tset_size(tid, ATTR1_LEN);
    assert(ret >= 0);

    /* Add 1st attribute on first group */
    aid = H5Acreate(gid, ATTR1, tid, sid, H5P_DEFAULT);
    assert(aid > 0);

    /* Close dataspace */
    ret = H5Sclose(sid);
    assert(ret >= 0);

    /* Close datatype */
    ret = H5Tclose(tid);
    assert(ret >= 0);

    /* Close attribute */
    ret = H5Aclose(aid);
    assert(ret >= 0);

    /* Create dataspace for 2nd attribute */
    sid = H5Screate(H5S_SCALAR);
    assert(sid > 0);

    /* Create dataype for attribute */
    tid = H5Tcopy(H5T_C_S1);
    assert(tid > 0);
    ret = H5Tset_size(tid, ATTR2_LEN);
    assert(ret >= 0);

    /* Add 2nd attribute on first group */
    aid = H5Acreate(gid, ATTR2, tid, sid, H5P_DEFAULT);
    assert(aid > 0);

    /* Close dataspace */
    ret = H5Sclose(sid);
    assert(ret >= 0);

    /* Close datatype */
    ret = H5Tclose(tid);
    assert(ret >= 0);

    /* Close 2nd attribute */
    ret = H5Aclose(aid);
    assert(ret >= 0);

    /* Close first group */
    ret = H5Gclose(gid);
    assert(ret >= 0);

    /* Close file */
    ret = H5Fclose(fid);
    assert(ret >= 0);


    /* Re-open file */
    fid = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    assert(fid > 0);

    /* Create third group */
    gid3 = H5Gcreate(fid, GROUP3, (size_t)0);
    assert(gid3 > 0);

    /* Close third group */
    ret = H5Gclose(gid3);
    assert(ret >= 0);

    /* Re-open first group */
    gid = H5Gopen(fid, GROUP1);
    assert(gid > 0);

    /* Delete 2nd attribute */
    ret = H5Adelete(gid, ATTR2);
    assert(ret >= 0);

    /* Close first group */
    ret = H5Gclose(gid);
    assert(ret >= 0);

    /* Close file */
    ret = H5Fclose(fid);
    assert(ret >= 0);




    /* Re-open file */
    fid = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    assert(fid > 0);

    /* Re-open first group */
    gid = H5Gopen(fid, GROUP1);
    assert(gid > 0);

    /* Create dataspace for 3rd attribute */
    sid = H5Screate(H5S_SCALAR);
    assert(sid > 0);

    /* Create dataype for attribute */
    tid = H5Tcopy(H5T_C_S1);
    assert(tid > 0);
    ret = H5Tset_size(tid, ATTR3_LEN);
    assert(ret >= 0);

    /* Add 3rd attribute on first group (smaller than 2nd attribute) */
    aid = H5Acreate(gid, ATTR3, tid, sid, H5P_DEFAULT);
    assert(aid > 0);

    /* Close dataspace */
    ret = H5Sclose(sid);
    assert(ret >= 0);

    /* Close datatype */
    ret = H5Tclose(tid);
    assert(ret >= 0);

    /* Close 3rd attribute */
    ret = H5Aclose(aid);
    assert(ret >= 0);

    /* Close first group */
    ret = H5Gclose(gid);
    assert(ret >= 0);

    /* Close file */
    ret = H5Fclose(fid);
    assert(ret >= 0);



    /* Re-open file */
    fid = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    assert(fid > 0);

    /* Re-open first group */
    gid = H5Gopen(fid, GROUP1);
    assert(gid > 0);

    /* Delete 3rd attribute */
    ret = H5Adelete(gid, ATTR3);
    assert(ret >= 0);

    /* Create dataspace for 3rd attribute */
    sid = H5Screate(H5S_SCALAR);
    assert(sid > 0);

    /* Create dataype for attribute */
    tid = H5Tcopy(H5T_C_S1);
    assert(tid > 0);
    ret = H5Tset_size(tid, ATTR2_LEN);
    assert(ret >= 0);

    /* Re-create 2nd attribute on first group */
    aid = H5Acreate(gid, ATTR2, tid, sid, H5P_DEFAULT);
    assert(aid > 0);

    /* Close dataspace */
    ret = H5Sclose(sid);
    assert(ret >= 0);

    /* Close datatype */
    ret = H5Tclose(tid);
    assert(ret >= 0);

    /* Close 2nd attribute */
    ret = H5Aclose(aid);
    assert(ret >= 0);

    /* Close first group */
    ret = H5Gclose(gid);
    assert(ret >= 0);

    /* Close file */
    ret = H5Fclose(fid);
    assert(ret >= 0);


    /* Re-open file */
    fid = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    assert(fid > 0);

    /* Re-open first group */
    gid = H5Gopen(fid, GROUP1);
    assert(gid > 0);

    /* Delete 2nd attribute */
    ret = H5Adelete(gid, ATTR2);
    assert(ret >= 0);

    /* Close first group */
    ret = H5Gclose(gid);
    assert(ret >= 0);

    /* Close file */
    ret = H5Fclose(fid);
    assert(ret >= 0);


    /* Re-open file */
    fid = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    assert(fid > 0);

    /* Re-open first group */
    gid = H5Gopen(fid, GROUP1);
    assert(gid > 0);

    /* Create dataspace for 3rd attribute */
    sid = H5Screate(H5S_SCALAR);
    assert(sid > 0);

    /* Create dataype for attribute */
    tid = H5Tcopy(H5T_C_S1);
    assert(tid > 0);
    ret = H5Tset_size(tid, ATTR2_LEN);
    assert(ret >= 0);

    /* Re-create 2nd attribute on first group */
    aid = H5Acreate(gid, ATTR2, tid, sid, H5P_DEFAULT);
    assert(aid > 0);

    /* Close dataspace */
    ret = H5Sclose(sid);
    assert(ret >= 0);

    /* Close datatype */
    ret = H5Tclose(tid);
    assert(ret >= 0);

    /* Close 2nd attribute */
    ret = H5Aclose(aid);
    assert(ret >= 0);

    /* Close first group */
    ret = H5Gclose(gid);
    assert(ret >= 0);

    /* Close file */
    ret = H5Fclose(fid);
    assert(ret >= 0);

    return(0);
}

