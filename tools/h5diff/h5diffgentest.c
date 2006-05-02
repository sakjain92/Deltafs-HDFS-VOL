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

#include <stdio.h>
#include <stdlib.h>
#include "hdf5.h"
#include "H5private.h"

/*-------------------------------------------------------------------------
 * Program: h5diffgentest
 *
 * Purpose: generate files for h5diff testting
 *
 * Programmer: Pedro Vicente, pvn@ncsa.uiuc.edu
 *
 * Date: November 12, 2003
 *
 *-------------------------------------------------------------------------
 */


#define UIMAX    4294967295u /*Maximum value for a variable of type unsigned int */
#define STR_SIZE 3
#define FILE1    "file1.h5"
#define FILE2    "file2.h5"
#define FILE3    "file3.h5"
#define FILE4    "file4.h5"
#define FILE5    "file5.h5"
#define FILE6    "file6.h5"
#define FILE7    "file7.h5"
#define FILE8    "file8.h5"


/*-------------------------------------------------------------------------
 * Function: write_attr
 *
 * Purpose: utility function to write an attribute in LOC_ID
 *
 *-------------------------------------------------------------------------
 */
static
int write_attr(hid_t loc_id,
               int rank,
               hsize_t *dims,
               const char *attr_name,
               hid_t tid,
               void *buf)
{
 hid_t   aid;
 hid_t   sid;
 herr_t  status;

 /* Create a buf space  */
 sid = H5Screate_simple(rank,dims,NULL);

 /* Create the attribute */
 aid = H5Acreate(loc_id,attr_name,tid,sid,H5P_DEFAULT);

 /* Write the buf */
 if ( buf )
  status = H5Awrite(aid,tid,buf);

 /* Close */
 status = H5Aclose(aid);
 status = H5Sclose(sid);
 return status;
}

/*-------------------------------------------------------------------------
 * Function: write_dset
 *
 * Purpose: utility function to create and write a dataset in LOC_ID
 *
 *-------------------------------------------------------------------------
 */
static
int write_dset( hid_t loc_id,
                int rank,
                hsize_t *dims,
                const char *dset_name,
                hid_t tid,
                void *buf )
{
 hid_t   did;
 hid_t   sid;
 herr_t  status;

 /* Create a buf space  */
 sid = H5Screate_simple(rank,dims,NULL);

 /* Create a dataset */
 did = H5Dcreate(loc_id,dset_name,tid,sid,H5P_DEFAULT);

 /* Write the buf */
 if ( buf )
  status = H5Dwrite(did,tid,H5S_ALL,H5S_ALL,H5P_DEFAULT,buf);

 /* Close */
 status = H5Dclose(did);
 status = H5Sclose(sid);

 return status;
}



/*

# ##############################################################################
# # Common usage
# ##############################################################################


# 1.0
 -h

# 1.1
 file1.h5 file2.h5 g1/dset1 g1/dset2

# 1.2
 file1.h5 file2.h5 -n 2 g1/dset1 g1/dset2

# 1.3
 file1.h5 file2.h5 -d 5 g1/dset3 g1/dset4

# 1.4
 file1.h5 file2.h5 -p 0.05 g1/dset3 g1/dset4

# 1.5
 file1.h5 file2.h5 -r g1/dset1 g1/dset2

# 1.6
 file1.h5 file2.h5

# ##############################################################################
# # basic types
# ##############################################################################

# 2.0
 file3.h5 file3.h5 dset group

# 2.1
 file3.h5 file3.h5 dset link

# 2.2
 file3.h5 file3.h5 dset type

# 2.3
 file3.h5 file3.h5 group group

# 2.4
 file3.h5 file3.h5 type type

# 2.5
 file3.h5 file3.h5 link link


# ##############################################################################
# # Dimensions
# ##############################################################################

# 4.0
 file5.h5 file5.h5 dset1 dset2

# 4.1
 file5.h5 file5.h5 dset3 dset4

# 4.2
 file5.h5 file5.h5 dset5 dset6


# ##############################################################################
# # Dataset types
# ##############################################################################

# 5.0
 file6.h5 file6.h5 dset0a dset0b

# 5.1
 file6.h5 file6.h5 dset1a dset1b

# 5.2
 file6.h5 file6.h5 dset2a dset2b

# 5.3
 file6.h5 file6.h5 dset3a dset4b

# 5.4
 file6.h5 file6.h5 dset4a dset4b

# 5.5
 file6.h5 file6.h5 dset5a dset5b

# 5.6
 file6.h5 file6.h5 dset6a dset6b

# 5.7
 file6.h5 file6.h5 dset7a dset7b

# 5.8
 file6.h5 file6.h5 dset8a dset8b

# ##############################################################################
# # Error messages
# ##############################################################################


# 6.0: Check if the command line number of arguments is less than 3
 h5diff_test1.h5

# 6.1: Check for invalid options
 h5diff_test1.h5 h5diff_test2.h5 -x

# ##############################################################################
# # -d
# ##############################################################################

# 6.2: no value
 file1.h5 file2.h5 -d g1/dset3 g1/dset4

# 6.3: negative value
 file1.h5 file2.h5 -d -4 g1/dset3 g1/dset4

# 6.4: zero
 file1.h5 file2.h5 -d 0 g1/dset3 g1/dset4

# 6.5: non number
 file1.h5 file2.h5 -d u g1/dset3 g1/dset4

# 6.6: hexadecimal
 file1.h5 file2.h5 -d 0x1 g1/dset3 g1/dset4

# 6.7: string
 file1.h5 file2.h5 -d "1" g1/dset3 g1/dset4

# 6.8: repeated option
 file1.h5 file2.h5 -d 1 -d 2 g1/dset3 g1/dset4

# 6.9: number larger than biggest difference
 file1.h5 file2.h5 -d 200 g1/dset3 g1/dset4

# 6.10: number smaller than smallest difference
 file1.h5 file2.h5 -d 1 g1/dset3 g1/dset4


# ##############################################################################
# # -p
# ##############################################################################


# 6.11: no value
 file1.h5 file2.h5 -p g1/dset3 g1/dset4

# 6.12: negative value
 file1.h5 file2.h5 -p -4 g1/dset3 g1/dset4

# 6.13: zero
 file1.h5 file2.h5 -p 0 g1/dset3 g1/dset4

# 6.14: non number
 file1.h5 file2.h5 -p u g1/dset3 g1/dset4

# 6.15: hexadecimal
 file1.h5 file2.h5 -p 0x1 g1/dset3 g1/dset4

# 6.16: string
 file1.h5 file2.h5 -p "0.21" g1/dset3 g1/dset4

# 6.17: repeated option
 file1.h5 file2.h5 -p 0.21 -p 0.22 g1/dset3 g1/dset4

# 6.18: number larger than biggest difference
 file1.h5 file2.h5 -p 2 g1/dset3 g1/dset4

# 6.19: number smaller than smallest difference
 file1.h5 file2.h5 -p 0.005 g1/dset3 g1/dset4



# ##############################################################################
# # -n
# ##############################################################################


# 6.20: no value
 file1.h5 file2.h5 -n g1/dset3 g1/dset4

# 6.21: negative value
 file1.h5 file2.h5 -n -4 g1/dset3 g1/dset4

# 6.22: zero
 file1.h5 file2.h5 -n 0 g1/dset3 g1/dset4

# 6.23: non number
 file1.h5 file2.h5 -n u g1/dset3 g1/dset4

# 6.24: hexadecimal
 file1.h5 file2.h5 -n 0x1 g1/dset3 g1/dset4

# 6.25: string
 file1.h5 file2.h5 -n "2" g1/dset3 g1/dset4

# 6.26: repeated option
 file1.h5 file2.h5 -n 2 -n 3 g1/dset3 g1/dset4

# 6.27: number larger than biggest difference
 file1.h5 file2.h5 -n 200 g1/dset3 g1/dset4

# 6.28: number smaller than smallest difference
 file1.h5 file2.h5 -n 1 g1/dset3 g1/dset4

# ##############################################################################
# # non valid files
# ##############################################################################

 file1.h6 file2.h6

*/


/*-------------------------------------------------------------------------
 * Function: gen_datareg
 *
 * Purpose: generate a dataset region and its reference
 *
 * Date: April 19, 2006
 *
 *-------------------------------------------------------------------------
 */

static 
void gen_datareg(hid_t fid,
                 int make_diffs /* flag to modify data buffers */)
{
 /* data dataset */
 hid_t           did1;              /* dataset ID   */
 hid_t           sid1;              /* dataspace ID  */
 hsize_t         dims1[2] = {10,10};/* dimensions */
 int             *buf;              /* dataset buffer */
 /* reference dataset */
 hid_t           did2;              /* dataset ID   */
 hid_t           sid2;              /* dataspace ID  */
 hsize_t         dims2[] = {2};     /* 2 references */
 hdset_reg_ref_t *rbuf;             /* buffer for write the references  */
 hsize_t         start[10];         /* starting location of hyperslab */
 hsize_t         count[10];         /* element count of hyperslab */
 hsize_t         coord[5][2];       /* coordinates for point selection */
 herr_t          status;
 int             i;

 /* allocate the buffer for write the references */
 rbuf=calloc(2,sizeof(hdset_reg_ref_t));

 /* allocate the buffer for write the data dataset */
 buf=malloc(10*10*sizeof(int));

 for (i=0; i<10*10; i++)
 {
  buf[i]=i; 
 }

 /* create the data dataset */
 sid1   = H5Screate_simple(2,dims1,NULL);
 did1   = H5Dcreate(fid,"dsetref",H5T_NATIVE_INT,sid1,H5P_DEFAULT);
 status = H5Dwrite(did1,H5T_NATIVE_INT,H5S_ALL,H5S_ALL,H5P_DEFAULT,buf);
 
 /* create the reference dataset */
 sid2   = H5Screate_simple(1,dims2,NULL);
 did2   = H5Dcreate(fid,"refreg",H5T_STD_REF_DSETREG,sid2,H5P_DEFAULT);

 /* create the references */
 /* select hyperslab for first reference */

 start[0]=2; start[1]=2;
 count[0]=6; count[1]=6;
 if (make_diffs)
 {
  start[0]=0; start[1]=0;
  count[0]=3; count[1]=3;
 }

 status = H5Sselect_hyperslab(sid1,H5S_SELECT_SET,start,NULL,count,NULL);
 H5Sget_select_npoints(sid1);

 /* store first dataset region */
 status = H5Rcreate(&rbuf[0],fid,"dsetref",H5R_DATASET_REGION,sid1);

 /* select sequence of five points for second reference */
 coord[0][0]=6; coord[0][1]=9;
 coord[1][0]=2; coord[1][1]=2;
 coord[2][0]=8; coord[2][1]=4;
 coord[3][0]=1; coord[3][1]=6;
 coord[4][0]=2; coord[4][1]=8;
 if (make_diffs)
 {
  coord[1][0]=3; coord[1][1]=3;
  coord[3][0]=2; coord[3][1]=5;
  coord[4][0]=1; coord[4][1]=7;
 }
 H5Sselect_elements(sid1,H5S_SELECT_SET,5,(const hsize_t **)coord);
 H5Sget_select_npoints(sid1);
 
 /* store second dataset region */
 H5Rcreate(&rbuf[1],fid,"dsetref",H5R_DATASET_REGION,sid1);

 /* write */
 status = H5Dwrite(did2,H5T_STD_REF_DSETREG,H5S_ALL,H5S_ALL,H5P_DEFAULT,rbuf);
 
 /* close, free memory buffers */
 status = H5Dclose(did1);
 status = H5Sclose(sid1);
 status = H5Dclose(did2);
 status = H5Sclose(sid2);
 free(rbuf);
 free(buf);

}

/*-------------------------------------------------------------------------
 * Function: write_dset_in
 *
 * Purpose: write datasets in LOC_ID
 *
 *-------------------------------------------------------------------------
 */
static 
void write_dset_in(hid_t loc_id,
                   const char* dset_name, /* for saving reference to dataset*/
                   hid_t fid,
                   int make_diffs /* flag to modify data buffers */)
{
 /* Compound datatype */
 typedef struct s_t
 {
  char   a;
  double b;
 } s_t;

 typedef enum
 {
  RED,
  GREEN
 } e_t;

 hid_t   did;
 hid_t   sid;
 hid_t   tid;
 hid_t   dcpl;
 herr_t  status;
 int     val, i, j, k, n;
 float   f;
 int     fillvalue=2;

 /* create 1D attributes with dimension [2], 2 elements */
 hsize_t    dims[1]={2};
 char       buf1[2][STR_SIZE]= {"ab","de"}; /* string */
 char       buf2[2]= {1,2};                 /* bitfield, opaque */
 s_t        buf3[2]= {{1,2},{3,4}};         /* compound */
 hobj_ref_t buf4[2];                        /* reference */
 e_t        buf45[2]= {RED,GREEN};          /* enum */
 hvl_t      buf5[2];                        /* vlen */
 hsize_t    dimarray[1]={3};                /* array dimension */
 int        buf6[2][3]= {{1,2,3},{4,5,6}};  /* array */
 int        buf7[2]= {1,2};                 /* integer */
 float      buf8[2]= {1,2};                 /* float */

 /* create 2D attributes with dimension [3][2], 6 elements */
 hsize_t    dims2[2]={3,2};
 char       buf12[6][STR_SIZE]= {"ab","cd","ef","gh","ij","kl"};  /* string */
 char       buf22[3][2]= {{1,2},{3,4},{5,6}};                     /* bitfield, opaque */
 s_t        buf32[6]= {{1,2},{3,4},{5,6},{7,8},{9,10},{11,12}};   /* compound */
 hobj_ref_t buf42[3][2];                                          /* reference */
 hvl_t      buf52[3][2];                                          /* vlen */
 int        buf62[6][3]= {{1,2,3},{4,5,6},{7,8,9},{10,11,12},{13,14,15},{16,17,18}};  /* array */
 int        buf72[3][2]= {{1,2},{3,4},{5,6}};                     /* integer */
 float      buf82[3][2]= {{1,2},{3,4},{5,6}};                     /* float */

 /* create 3D attributes with dimension [4][3][2], 24 elements */
 hsize_t    dims3[3]={4,3,2};
 char       buf13[24][STR_SIZE]= {"ab","cd","ef","gh","ij","kl","mn","pq",
 "rs","tu","vw","xz","AB","CD","EF","GH",
 "IJ","KL","MN","PQ","RS","TU","VW","XZ"};  /* string */
 char       buf23[4][3][2];    /* bitfield, opaque */
 s_t        buf33[4][3][2];    /* compound */
 hobj_ref_t buf43[4][3][2];    /* reference */
 hvl_t      buf53[4][3][2];    /* vlen */
 int        buf63[24][3];      /* array */
 int        buf73[4][3][2];    /* integer */
 float      buf83[4][3][2];    /* float */


/*-------------------------------------------------------------------------
 * 1D
 *-------------------------------------------------------------------------
 */

/*-------------------------------------------------------------------------
 * H5T_STRING
 *-------------------------------------------------------------------------
 */


 if (make_diffs)
 {
  for (i=0; i<2; i++)
   for (j=0; j<2; j++)
   {
    buf1[i][j]='z';
   }
 }


 tid = H5Tcopy(H5T_C_S1);
 status  = H5Tset_size(tid,STR_SIZE);
 write_dset(loc_id,1,dims,"string",tid,buf1);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_BITFIELD
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
   buf2[i]=buf2[1]=0;
 }

 tid = H5Tcopy(H5T_STD_B8LE);
 write_dset(loc_id,1,dims,"bitfield",tid,buf2);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_OPAQUE
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
  {
   buf3[i].a=0; buf3[i].b=0;
  }
 }

 tid = H5Tcreate(H5T_OPAQUE, 1);
 status = H5Tset_tag(tid, "1-byte opaque type"); /* must set this */
 write_dset(loc_id,1,dims,"opaque",tid,buf2);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_COMPOUND
 *-------------------------------------------------------------------------
 */


 if (make_diffs)
 {
  for (i=0; i<2; i++)
  {
   buf45[i]=GREEN;
  }
 }

 tid = H5Tcreate (H5T_COMPOUND, sizeof(s_t));
 H5Tinsert(tid, "a", HOFFSET(s_t, a), H5T_NATIVE_CHAR);
 H5Tinsert(tid, "b", HOFFSET(s_t, b), H5T_NATIVE_DOUBLE);
 write_dset(loc_id,1,dims,"compound",tid,buf3);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_REFERENCE (H5R_OBJECT object reference)
 *-------------------------------------------------------------------------
 */
 /* Create references to dataset */
 if (dset_name)
 {
  status=H5Rcreate(&buf4[0],fid,dset_name,H5R_OBJECT,-1);
  status=H5Rcreate(&buf4[1],fid,dset_name,H5R_OBJECT,-1);
  write_dset(loc_id,1,dims,"reference",H5T_STD_REF_OBJ,buf4);
 }

/*-------------------------------------------------------------------------
 * H5T_REFERENCE (H5R_DATASET_REGION dataset region reference)
 *-------------------------------------------------------------------------
 */

 gen_datareg(fid,make_diffs);

/*-------------------------------------------------------------------------
 * H5T_ENUM
 *-------------------------------------------------------------------------
 */
 tid = H5Tcreate(H5T_ENUM, sizeof(e_t));
 H5Tenum_insert(tid, "RED",   (val = 0, &val));
 H5Tenum_insert(tid, "GREEN", (val = 1, &val));
 write_dset(loc_id,1,dims,"enum",tid,buf45);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_VLEN
 *-------------------------------------------------------------------------
 */

 /* Allocate and initialize VL dataset to write */

 buf5[0].len = 1;
 buf5[0].p = malloc( 1 * sizeof(int));
 ((int *)buf5[0].p)[0]=1;
 buf5[1].len = 2;
 buf5[1].p = malloc( 2 * sizeof(int));
 ((int *)buf5[1].p)[0]=2;
 ((int *)buf5[1].p)[1]=3;

 if (make_diffs)
 {
  ((int *)buf5[0].p)[0]=0;
  ((int *)buf5[1].p)[0]=0;
  ((int *)buf5[1].p)[1]=0;
 }

 sid = H5Screate_simple(1,dims,NULL);
 tid = H5Tvlen_create(H5T_NATIVE_INT);
 did = H5Dcreate(loc_id,"vlen",tid,sid,H5P_DEFAULT);
 status = H5Dwrite(did,tid,H5S_ALL,H5S_ALL,H5P_DEFAULT,buf5);
 assert(status>=0);
 status = H5Dvlen_reclaim(tid,sid,H5P_DEFAULT,buf5);
 assert(status>=0);
 status = H5Dclose(did);
 status = H5Tclose(tid);
 status = H5Sclose(sid);

/*-------------------------------------------------------------------------
 * H5T_ARRAY
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
   for (j=0; j<3; j++)
   {
    buf6[i][j]=0;
   }
 }

 tid = H5Tarray_create(H5T_NATIVE_INT,1,dimarray,NULL);
 write_dset(loc_id,1,dims,"array",tid,buf6);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_INTEGER and H5T_FLOAT
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
  {
   buf7[i]=0;
   buf8[i]=0;
  }
 }

 write_dset(loc_id,1,dims,"integer",H5T_NATIVE_INT,buf7);
 write_dset(loc_id,1,dims,"float",H5T_NATIVE_FLOAT,buf8);


/*-------------------------------------------------------------------------
 * 2D
 *-------------------------------------------------------------------------
 */

/*-------------------------------------------------------------------------
 * H5T_STRING
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  memset(buf12, 'z', sizeof buf12);
 }


 tid = H5Tcopy(H5T_C_S1);
 status  = H5Tset_size(tid,STR_SIZE);
 write_dset(loc_id,2,dims2,"string2D",tid,buf12);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_BITFIELD
 *-------------------------------------------------------------------------
 */


 if (make_diffs)
 {
  memset(buf22,0,sizeof buf22);
 }

 tid = H5Tcopy(H5T_STD_B8LE);
 write_dset(loc_id,2,dims2,"bitfield2D",tid,buf22);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_OPAQUE
 *-------------------------------------------------------------------------
 */
 tid = H5Tcreate(H5T_OPAQUE, 1);
 status = H5Tset_tag(tid, "1-byte opaque type"); /* must set this */
 write_dset(loc_id,2,dims2,"opaque2D",tid,buf22);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_COMPOUND
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  memset(buf32,0,sizeof buf32);
 }

 tid = H5Tcreate (H5T_COMPOUND, sizeof(s_t));
 H5Tinsert(tid, "a", HOFFSET(s_t, a), H5T_NATIVE_CHAR);
 H5Tinsert(tid, "b", HOFFSET(s_t, b), H5T_NATIVE_DOUBLE);
 write_dset(loc_id,2,dims2,"compound2D",tid,buf32);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_REFERENCE (H5R_OBJECT object reference)
 *-------------------------------------------------------------------------
 */
 /* Create references to dataset */
 if (dset_name)
 {
  for (i = 0; i < 3; i++) {
   for (j = 0; j < 2; j++) {
    status=H5Rcreate(&buf42[i][j],fid,dset_name,H5R_OBJECT,-1);
   }
  }
  write_dset(loc_id,2,dims2,"reference2D",H5T_STD_REF_OBJ,buf42);
 }

/*-------------------------------------------------------------------------
 * H5T_ENUM
 *-------------------------------------------------------------------------
 */

 tid = H5Tcreate(H5T_ENUM, sizeof(e_t));
 H5Tenum_insert(tid, "RED",   (val = 0, &val));
 H5Tenum_insert(tid, "GREEN", (val = 1, &val));
 write_dset(loc_id,2,dims2,"enum2D",tid,0);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_VLEN
 *-------------------------------------------------------------------------
 */

/* Allocate and initialize VL dataset to write */
 n=0;
 for (i = 0; i < 3; i++) {
  for (j = 0; j < 2; j++) {
    int l;
    buf52[i][j].p = malloc((i + 1) * sizeof(int));
    buf52[i][j].len = i + 1;
    for (l = 0; l < i + 1; l++)
    if (make_diffs)((int *)buf52[i][j].p)[l] = 0;
    else ((int *)buf52[i][j].p)[l] = n++;
  }
 }

 sid = H5Screate_simple(2,dims2,NULL);
 tid = H5Tvlen_create(H5T_NATIVE_INT);
 did = H5Dcreate(loc_id,"vlen2D",tid,sid,H5P_DEFAULT);
 status = H5Dwrite(did,tid,H5S_ALL,H5S_ALL,H5P_DEFAULT,buf52);
 assert(status>=0);
 status = H5Dvlen_reclaim(tid,sid,H5P_DEFAULT,buf52);
 assert(status>=0);
 status = H5Dclose(did);
 status = H5Tclose(tid);
 status = H5Sclose(sid);

/*-------------------------------------------------------------------------
 * H5T_ARRAY
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  memset(buf62,0,sizeof buf62);
 }


 tid = H5Tarray_create(H5T_NATIVE_INT,1,dimarray,NULL);
 write_dset(loc_id,2,dims2,"array2D",tid,buf62);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_INTEGER, write a fill value
 *-------------------------------------------------------------------------
 */


 if (make_diffs)
 {
  memset(buf72,0,sizeof buf72);
  memset(buf82,0,sizeof buf82);
 }


 dcpl = H5Pcreate(H5P_DATASET_CREATE);
 status = H5Pset_fill_value(dcpl, H5T_NATIVE_INT, &fillvalue);
 sid = H5Screate_simple(2,dims2,NULL);
 did = H5Dcreate(loc_id,"integer2D",H5T_NATIVE_INT,sid,dcpl);
 status = H5Dwrite(did,H5T_NATIVE_INT,H5S_ALL,H5S_ALL,H5P_DEFAULT,buf72);
 status = H5Pclose(dcpl);
 status = H5Dclose(did);
 status = H5Sclose(sid);

/*-------------------------------------------------------------------------
 * H5T_FLOAT
 *-------------------------------------------------------------------------
 */

 write_dset(loc_id,2,dims2,"float2D",H5T_NATIVE_FLOAT,buf82);


/*-------------------------------------------------------------------------
 * 3D
 *-------------------------------------------------------------------------
 */

/*-------------------------------------------------------------------------
 * H5T_STRING
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  memset(buf13,'z',sizeof buf13);
 }

 tid = H5Tcopy(H5T_C_S1);
 status  = H5Tset_size(tid,STR_SIZE);
 write_dset(loc_id,3,dims3,"string3D",tid,buf13);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_BITFIELD
 *-------------------------------------------------------------------------
 */


 n=1;
 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    if (make_diffs) buf23[i][j][k]=0;
    else buf23[i][j][k]=n++;
   }
  }
 }


 tid = H5Tcopy(H5T_STD_B8LE);
 write_dset(loc_id,3,dims3,"bitfield3D",tid,buf23);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_OPAQUE
 *-------------------------------------------------------------------------
 */
 tid = H5Tcreate(H5T_OPAQUE, 1);
 status = H5Tset_tag(tid, "1-byte opaque type"); /* must set this */
 write_dset(loc_id,3,dims3,"opaque3D",tid,buf23);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_COMPOUND
 *-------------------------------------------------------------------------
 */

 n=1;
 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    if (make_diffs) {
     buf33[i][j][k].a=0;
     buf33[i][j][k].b=0;
    }
    else {
     buf33[i][j][k].a=n++;
     buf33[i][j][k].b=n++;
    }
   }
  }
 }


 tid = H5Tcreate (H5T_COMPOUND, sizeof(s_t));
 H5Tinsert(tid, "a", HOFFSET(s_t, a), H5T_NATIVE_CHAR);
 H5Tinsert(tid, "b", HOFFSET(s_t, b), H5T_NATIVE_DOUBLE);
 write_dset(loc_id,3,dims3,"compound3D",tid,buf33);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_REFERENCE (H5R_OBJECT object reference)
 *-------------------------------------------------------------------------
 */
 /* Create references to dataset */
 if (dset_name)
 {
  for (i = 0; i < 4; i++) {
   for (j = 0; j < 3; j++) {
    for (k = 0; k < 2; k++)
     status=H5Rcreate(&buf43[i][j][k],fid,dset_name,H5R_OBJECT,-1);
   }
  }
 write_dset(loc_id,3,dims3,"reference3D",H5T_STD_REF_OBJ,buf43);
 }

/*-------------------------------------------------------------------------
 * H5T_ENUM
 *-------------------------------------------------------------------------
 */

 tid = H5Tcreate(H5T_ENUM, sizeof(e_t));
 H5Tenum_insert(tid, "RED",   (val = 0, &val));
 H5Tenum_insert(tid, "GREEN", (val = 1, &val));
 write_dset(loc_id,3,dims3,"enum3D",tid,0);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_VLEN
 *-------------------------------------------------------------------------
 */

 /* Allocate and initialize VL dataset to write */
 n=0;
 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    int l;
    buf53[i][j][k].p = malloc((i + 1) * sizeof(int));
    buf53[i][j][k].len = i + 1;
    for (l = 0; l < i + 1; l++)
    if (make_diffs)((int *)buf53[i][j][k].p)[l] = 0;
    else ((int *)buf53[i][j][k].p)[l] = n++;
   }
  }
 }

 sid = H5Screate_simple(3,dims3,NULL);
 tid = H5Tvlen_create(H5T_NATIVE_INT);
 did = H5Dcreate(loc_id,"vlen3D",tid,sid,H5P_DEFAULT);
 status = H5Dwrite(did,tid,H5S_ALL,H5S_ALL,H5P_DEFAULT,buf53);
 assert(status>=0);
 status = H5Dvlen_reclaim(tid,sid,H5P_DEFAULT,buf53);
 assert(status>=0);
 status = H5Dclose(did);
 status = H5Tclose(tid);
 status = H5Sclose(sid);

/*-------------------------------------------------------------------------
 * H5T_ARRAY
 *-------------------------------------------------------------------------
 */


 n=1;
 for (i = 0; i < 24; i++) {
  for (j = 0; j < (int)dimarray[0]; j++) {
    if (make_diffs) buf63[i][j]=0;
    else buf63[i][j]=n++;
  }
 }

 tid = H5Tarray_create(H5T_NATIVE_INT,1,dimarray,NULL);
 write_dset(loc_id,3,dims3,"array3D",tid,buf63);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_INTEGER and H5T_FLOAT
 *-------------------------------------------------------------------------
 */
 n=1; f=1;
 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    if (make_diffs) {
     buf73[i][j][k]=0;
     buf83[i][j][k]=0;
    }
    else {
     buf73[i][j][k]=n++;
     buf83[i][j][k]=f++;
    }
   }
  }
 }
 write_dset(loc_id,3,dims3,"integer3D",H5T_NATIVE_INT,buf73);
 write_dset(loc_id,3,dims3,"float3D",H5T_NATIVE_FLOAT,buf83);
}




/*-------------------------------------------------------------------------
 * Function: write_attr_in
 *
 * Purpose: write attributes in LOC_ID (dataset, group, named datatype)
 *
 *-------------------------------------------------------------------------
 */
static 
void write_attr_in(hid_t loc_id,
                   const char* dset_name, /* for saving reference to dataset*/
                   hid_t fid,
                   int make_diffs /* flag to modify data buffers */)
{
 /* Compound datatype */
 typedef struct s_t
 {
  char   a;
  double b;
 } s_t;

 typedef enum
 {
  RED,
  GREEN
 } e_t;

 hid_t   aid;
 hid_t   sid;
 hid_t   tid;
 herr_t  status;
 int     val, i, j, k, n;
 float   f;

 /* create 1D attributes with dimension [2], 2 elements */
 hsize_t    dims[1]={2};
 char       buf1[2][2]= {"ab","de"};        /* string */
 char       buf2[2]= {1,2};                 /* bitfield, opaque */
 s_t        buf3[2]= {{1,2},{3,4}};         /* compound */
 hobj_ref_t buf4[2];                        /* reference */
 e_t        buf45[2]= {RED,RED};            /* enum */
 hvl_t      buf5[2];                        /* vlen */
 hsize_t    dimarray[1]={3};                /* array dimension */
 int        buf6[2][3]= {{1,2,3},{4,5,6}};  /* array */
 int        buf7[2]= {1,2};                 /* integer */
 float      buf8[2]= {1,2};                 /* float */

 /* create 2D attributes with dimension [3][2], 6 elements */
 hsize_t    dims2[2]={3,2};
 char       buf12[6][2]= {"ab","cd","ef","gh","ij","kl"};         /* string */
 char       buf22[3][2]= {{1,2},{3,4},{5,6}};                     /* bitfield, opaque */
 s_t        buf32[6]= {{1,2},{3,4},{5,6},{7,8},{9,10},{11,12}};   /* compound */
 hobj_ref_t buf42[3][2];                                          /* reference */
 e_t        buf452[3][2];                                         /* enum */
 hvl_t      buf52[3][2];                                          /* vlen */
 int        buf62[6][3]= {{1,2,3},{4,5,6},{7,8,9},{10,11,12},{13,14,15},{16,17,18}};  /* array */
 int        buf72[3][2]= {{1,2},{3,4},{5,6}};                     /* integer */
 float      buf82[3][2]= {{1,2},{3,4},{5,6}};                     /* float */

 /* create 3D attributes with dimension [4][3][2], 24 elements */
 hsize_t    dims3[3]={4,3,2};
 char       buf13[24][2]= {"ab","cd","ef","gh","ij","kl","mn","pq",
 "rs","tu","vw","xz","AB","CD","EF","GH",
 "IJ","KL","MN","PQ","RS","TU","VW","XZ"};  /* string */
 char       buf23[4][3][2];    /* bitfield, opaque */
 s_t        buf33[4][3][2];    /* compound */
 hobj_ref_t buf43[4][3][2];    /* reference */
 e_t        buf453[4][3][2];   /* enum */
 hvl_t      buf53[4][3][2];    /* vlen */
 int        buf63[24][3];      /* array */
 int        buf73[4][3][2];    /* integer */
 float      buf83[4][3][2];    /* float */


/*-------------------------------------------------------------------------
 * 1D attributes
 *-------------------------------------------------------------------------
 */

/*-------------------------------------------------------------------------
 * H5T_STRING
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
   for (j=0; j<2; j++)
   {
    buf1[i][j]='z';
   }
 }
 /*
 buf1[2][2]= {"ab","de"};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
 Attribute:   <string> and <string>
 position      string of </g1>  string of </g1> difference
 ------------------------------------------------------------
[ 0 ]          a                z
[ 0 ]          b                z
[ 1 ]          d                z
[ 1 ]          e                z
 */
 tid = H5Tcopy(H5T_C_S1);
 status  = H5Tset_size(tid, 2);
 write_attr(loc_id,1,dims,"string",tid,buf1);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_BITFIELD
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
   buf2[i]=buf2[1]=0;
 }
 /*
 buf2[2]= {1,2};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
 Attribute:   <bitfield> and <bitfield>
 position      bitfield of </g1> bitfield of </g1> difference
 position        opaque of </g1> opaque of </g1> difference
------------------------------------------------------------
[ 0 ]          1               0               1
[ 1 ]          2               0               2
 */

 tid = H5Tcopy(H5T_STD_B8LE);
 write_attr(loc_id,1,dims,"bitfield",tid,buf2);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_OPAQUE
 *-------------------------------------------------------------------------
 */

 /*
 buf2[2]= {1,2};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
 Attribute:   <opaque> and <opaque>
 position     opaque of </g1> opaque of </g1> difference
 position        opaque of </g1> opaque of </g1> difference
------------------------------------------------------------
[ 0 ]          1               0               1
[ 1 ]          2               0               2
*/

 tid = H5Tcreate(H5T_OPAQUE, 1);
 status = H5Tset_tag(tid, "1-byte opaque type"); /* must set this */
 write_attr(loc_id,1,dims,"opaque",tid,buf2);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_COMPOUND
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
  {
   buf3[i].a=0; buf3[i].b=0;
  }
 }

 /*
 buf3[2]= {{1,2},{3,4}};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
 Attribute:   <compound> and <compound>
 position        compound of </g1> compound of </g1> difference
 ------------------------------------------------------------
 [ 0 ]          1               5               4
 [ 0 ]          2               5               3
 [ 1 ]          3               5               2
 [ 1 ]          4               5               1
 */

 tid = H5Tcreate (H5T_COMPOUND, sizeof(s_t));
 H5Tinsert(tid, "a", HOFFSET(s_t, a), H5T_NATIVE_CHAR);
 H5Tinsert(tid, "b", HOFFSET(s_t, b), H5T_NATIVE_DOUBLE);
 write_attr(loc_id,1,dims,"compound",tid,buf3);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_REFERENCE (H5R_OBJECT object reference)
 *-------------------------------------------------------------------------
 */
 /* Create references to dataset */
 if (dset_name)
 {
  status=H5Rcreate(&buf4[0],fid,dset_name,H5R_OBJECT,-1);
  status=H5Rcreate(&buf4[1],fid,dset_name,H5R_OBJECT,-1);
  write_attr(loc_id,1,dims,"reference",H5T_STD_REF_OBJ,buf4);
 }

/*-------------------------------------------------------------------------
 * H5T_ENUM
 *-------------------------------------------------------------------------
 */
 if (make_diffs)
 {
  for (i=0; i<2; i++)
  {
   buf45[i]=GREEN;
  }
 }
 /*
 buf45[2]= {RED,RED};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
 Attribute:   <enum> and <enum>
 position     enum of </g1>   enum of </g1>   difference
------------------------------------------------------------
[ 0 ]          RED              GREEN
[ 1 ]          RED              GREEN
 */
 tid = H5Tcreate(H5T_ENUM, sizeof(e_t));
 H5Tenum_insert(tid, "RED",   (val = 0, &val));
 H5Tenum_insert(tid, "GREEN", (val = 1, &val));
 write_attr(loc_id,1,dims,"enum",tid,buf45);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_VLEN
 *-------------------------------------------------------------------------
 */

 /* Allocate and initialize VL dataset to write */

 buf5[0].len = 1;
 buf5[0].p = malloc( 1 * sizeof(int));
 ((int *)buf5[0].p)[0]=1;
 buf5[1].len = 2;
 buf5[1].p = malloc( 2 * sizeof(int));
 ((int *)buf5[1].p)[0]=2;
 ((int *)buf5[1].p)[1]=3;

 if (make_diffs)
 {
  ((int *)buf5[0].p)[0]=0;
  ((int *)buf5[1].p)[0]=0;
  ((int *)buf5[1].p)[1]=0;
 }
 /*
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
 position        vlen of </g1>   vlen of </g1>   difference
------------------------------------------------------------
[ 0 ]          1               0               1
[ 1 ]          2               0               2
[ 1 ]          3               0               3
 */

 sid = H5Screate_simple(1,dims,NULL);
 tid = H5Tvlen_create(H5T_NATIVE_INT);
 aid = H5Acreate(loc_id,"vlen",tid,sid,H5P_DEFAULT);
 status = H5Awrite(aid,tid,buf5);
 assert(status>=0);
 status = H5Dvlen_reclaim(tid,sid,H5P_DEFAULT,buf5);
 assert(status>=0);
 status = H5Aclose(aid);
 status = H5Tclose(tid);
 status = H5Sclose(sid);

/*-------------------------------------------------------------------------
 * H5T_ARRAY
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
   for (j=0; j<3; j++)
   {
    buf6[i][j]=0;
   }
 }
 /*
 buf6[2][3]= {{1,2,3},{4,5,6}};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
 Attribute:   <array> and <array>
position        array of </g1>  array of </g1>  difference
------------------------------------------------------------
[ 0 ]          1               0               1
[ 0 ]          2               0               2
[ 0 ]          3               0               3
[ 1 ]          4               0               4
[ 1 ]          5               0               5
[ 1 ]          6               0               6
 */
 tid = H5Tarray_create(H5T_NATIVE_INT,1,dimarray,NULL);
 write_attr(loc_id,1,dims,"array",tid,buf6);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_INTEGER and H5T_FLOAT
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  for (i=0; i<2; i++)
  {
   buf7[i]=0;
   buf8[i]=0;
  }
 }
 /*
 buf7[2]= {1,2};
 buf8[2]= {1,2};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
 position        integer of </g1> integer of </g1> difference
 ------------------------------------------------------------
 [ 0 ]          1               0               1
 [ 1 ]          2               0               2
 position        float of </g1>  float of </g1>  difference
 ------------------------------------------------------------
 [ 0 ]          1               0               1
 [ 1 ]          2               0               2
 */
 write_attr(loc_id,1,dims,"integer",H5T_NATIVE_INT,buf7);
 write_attr(loc_id,1,dims,"float",H5T_NATIVE_FLOAT,buf8);


/*-------------------------------------------------------------------------
 * 2D attributes
 *-------------------------------------------------------------------------
 */

/*-------------------------------------------------------------------------
 * H5T_STRING
 *-------------------------------------------------------------------------
 */
 if (make_diffs)
 {
  memset(buf12, 'z', sizeof buf12);
 }

 /*
 buf12[6][2]= {"ab","cd","ef","gh","ij","kl"};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Attribute:   <string2D> and <string2D>
 position        string2D of </g1> string2D of </g1> difference
 ------------------------------------------------------------
[ 0 0 ]          a                z
[ 0 0 ]          b                z
[ 0 1 ]          c                z
[ 0 1 ]          d                z
[ 1 0 ]          e                z
[ 1 0 ]          f                z
[ 1 1 ]          g                z
[ 1 1 ]          h                z
[ 2 0 ]          i                z
[ 2 0 ]          j                z
[ 2 1 ]          k                z
[ 2 1 ]          l                z
 */

 tid = H5Tcopy(H5T_C_S1);
 status  = H5Tset_size(tid, 2);
 write_attr(loc_id,2,dims2,"string2D",tid,buf12);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_BITFIELD
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  memset(buf22,0,sizeof buf22);
 }

 /*
 buf22[3][2]= {{1,2},{3,4},{5,6}};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Attribute:   <bitfield2D> and <bitfield2D>
 position        bitfield2D of </g1> bitfield2D of </g1> difference
------------------------------------------------------------
[ 0 0 ]          1               0               1
[ 0 1 ]          2               0               2
[ 1 0 ]          3               0               3
[ 1 1 ]          4               0               4
[ 2 0 ]          5               0               5
[ 2 1 ]          6               0               6
 */


 tid = H5Tcopy(H5T_STD_B8LE);
 write_attr(loc_id,2,dims2,"bitfield2D",tid,buf22);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_OPAQUE
 *-------------------------------------------------------------------------
 */

 /*
 buf22[3][2]= {{1,2},{3,4},{5,6}};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Attribute:   <opaque2D> and <opaque2D>
 position        opaque2D of </g1> opaque2D of </g1> difference
------------------------------------------------------------
[ 0 0 ]          1               0               1
[ 0 1 ]          2               0               2
[ 1 0 ]          3               0               3
[ 1 1 ]          4               0               4
[ 2 0 ]          5               0               5
[ 2 1 ]          6               0               6
 */
 tid = H5Tcreate(H5T_OPAQUE, 1);
 status = H5Tset_tag(tid, "1-byte opaque type"); /* must set this */
 write_attr(loc_id,2,dims2,"opaque2D",tid,buf22);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_COMPOUND
 *-------------------------------------------------------------------------
 */
 if (make_diffs)
 {
  memset(buf32,0,sizeof buf32);
 }

 /*
 buf32[6]= {{1,2},{3,4},{5,6},{7,8},{9,10},{11,12}};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Attribute:   <opaque2D> and <opaque2D>
 position        opaque2D of </g1> opaque2D of </g1> difference
------------------------------------------------------------
[ 0 0 ]          1               0               1
[ 0 1 ]          2               0               2
[ 1 0 ]          3               0               3
[ 1 1 ]          4               0               4
[ 2 0 ]          5               0               5
[ 2 1 ]          6               0               6
 */


 tid = H5Tcreate (H5T_COMPOUND, sizeof(s_t));
 H5Tinsert(tid, "a", HOFFSET(s_t, a), H5T_NATIVE_CHAR);
 H5Tinsert(tid, "b", HOFFSET(s_t, b), H5T_NATIVE_DOUBLE);
 write_attr(loc_id,2,dims2,"compound2D",tid,buf32);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_REFERENCE (H5R_OBJECT object reference)
 *-------------------------------------------------------------------------
 */
 /* Create references to dataset */
 if (dset_name)
 {
  for (i = 0; i < 3; i++) {
   for (j = 0; j < 2; j++) {
    status=H5Rcreate(&buf42[i][j],fid,dset_name,H5R_OBJECT,-1);
   }
  }
  write_attr(loc_id,2,dims2,"reference2D",H5T_STD_REF_OBJ,buf42);
 }

/*-------------------------------------------------------------------------
 * H5T_ENUM
 *-------------------------------------------------------------------------
 */
 for (i=0; i<3; i++)
  for (j=0; j<2; j++)
  {
   if (make_diffs) buf452[i][j]=GREEN; else buf452[i][j]=RED;
  }

/*
Attribute:   <enum2D> and <enum2D>
position        enum2D of </g1> enum2D of </g1> difference
------------------------------------------------------------
[ 0 0 ]          RED              GREEN
[ 0 1 ]          RED              GREEN
[ 1 0 ]          RED              GREEN
[ 1 1 ]          RED              GREEN
[ 2 0 ]          RED              GREEN
[ 2 1 ]          RED              GREEN
*/

 tid = H5Tcreate(H5T_ENUM, sizeof(e_t));
 H5Tenum_insert(tid, "RED",   (val = 0, &val));
 H5Tenum_insert(tid, "GREEN", (val = 1, &val));
 write_attr(loc_id,2,dims2,"enum2D",tid,buf452);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_VLEN
 *-------------------------------------------------------------------------
 */

 /* Allocate and initialize VL dataset to write */
 n=0;
 for (i = 0; i < 3; i++) {
  for (j = 0; j < 2; j++) {
    int l;
    buf52[i][j].p = malloc((i + 1) * sizeof(int));
    buf52[i][j].len = i + 1;
    for (l = 0; l < i + 1; l++)
    if (make_diffs)((int *)buf52[i][j].p)[l] = 0;
    else ((int *)buf52[i][j].p)[l] = n++;
  }
 }

 /*
 position        vlen2D of </g1> vlen2D of </g1> difference
------------------------------------------------------------
[ 0 1 ]          1               0               1
[ 1 0 ]          2               0               2
[ 1 0 ]          3               0               3
[ 1 1 ]          4               0               4
[ 1 1 ]          5               0               5
[ 2 0 ]          6               0               6
[ 2 0 ]          7               0               7
[ 2 0 ]          8               0               8
[ 2 1 ]          9               0               9
[ 2 1 ]          10              0               10
[ 2 1 ]          11              0               11
*/

 sid = H5Screate_simple(2,dims2,NULL);
 tid = H5Tvlen_create(H5T_NATIVE_INT);
 aid = H5Acreate(loc_id,"vlen2D",tid,sid,H5P_DEFAULT);
 status = H5Awrite(aid,tid,buf52);
 assert(status>=0);
 status = H5Dvlen_reclaim(tid,sid,H5P_DEFAULT,buf52);
 assert(status>=0);
 status = H5Aclose(aid);
 status = H5Tclose(tid);
 status = H5Sclose(sid);

/*-------------------------------------------------------------------------
 * H5T_ARRAY
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  memset(buf62,0,sizeof buf62);
 }
 /*
 buf62[6][3]= {{1,2,3},{4,5,6},{7,8,9},{10,11,12},{13,14,15},{16,17,18}};
 $h5diff file7.h5 file6.h5 g1 g1 -v
 Group:       </g1> and </g1>
Attribute:   <array2D> and <array2D>
position        array2D of </g1> array2D of </g1> difference
------------------------------------------------------------
[ 0 0 ]          1               0               1
[ 0 0 ]          2               0               2
[ 0 0 ]          3               0               3
[ 0 1 ]          4               0               4
[ 0 1 ]          5               0               5
[ 0 1 ]          6               0               6
[ 1 0 ]          7               0               7
[ 1 0 ]          8               0               8
[ 1 0 ]          9               0               9
[ 1 1 ]          10              0               10
[ 1 1 ]          11              0               11
[ 1 1 ]          12              0               12
[ 2 0 ]          13              0               13
[ 2 0 ]          14              0               14
[ 2 0 ]          15              0               15
[ 2 1 ]          16              0               16
[ 2 1 ]          17              0               17
[ 2 1 ]          18              0               18
 */
 tid = H5Tarray_create(H5T_NATIVE_INT,1,dimarray,NULL);
 write_attr(loc_id,2,dims2,"array2D",tid,buf62);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_INTEGER and H5T_FLOAT
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  memset(buf72,0,sizeof buf72);
  memset(buf82,0,sizeof buf82);
 }
/*
Attribute:   <integer2D> and <integer2D>
position        integer2D of </g1> integer2D of </g1> difference
------------------------------------------------------------
[ 0 0 ]          1               0               1
[ 0 1 ]          2               0               2
[ 1 0 ]          3               0               3
[ 1 1 ]          4               0               4
[ 2 0 ]          5               0               5
[ 2 1 ]          6               0               6
6 differences found
Attribute:   <float2D> and <float2D>
position        float2D of </g1> float2D of </g1> difference
------------------------------------------------------------
[ 0 0 ]          1               0               1
[ 0 1 ]          2               0               2
[ 1 0 ]          3               0               3
[ 1 1 ]          4               0               4
[ 2 0 ]          5               0               5
[ 2 1 ]          6               0               6
*/

 write_attr(loc_id,2,dims2,"integer2D",H5T_NATIVE_INT,buf72);
 write_attr(loc_id,2,dims2,"float2D",H5T_NATIVE_FLOAT,buf82);


/*-------------------------------------------------------------------------
 * 3D attributes
 *-------------------------------------------------------------------------
 */

/*-------------------------------------------------------------------------
 * H5T_STRING
 *-------------------------------------------------------------------------
 */

 if (make_diffs)
 {
  memset(buf13,'z',sizeof buf13);
 }

 /*
 buf13[24][2]= {"ab","cd","ef","gh","ij","kl","mn","pq",
 "rs","tu","vw","xz","AB","CD","EF","GH",
 "IJ","KL","MN","PQ","RS","TU","VW","XZ"};

Attribute:   <string3D> and <string3D>
position        string3D of </g1> string3D of </g1> difference
------------------------------------------------------------
[ 0 0 0 ]          a                z
[ 0 0 0 ]          b                z
[ 0 0 1 ]          c                z
[ 0 0 1 ]          d                z
[ 0 1 0 ]          e                z
[ 0 1 0 ]          f                z
[ 0 1 1 ]          g                z
[ 0 1 1 ]          h                z
[ 0 2 0 ]          i                z
[ 0 2 0 ]          j                z
[ 0 2 1 ]          k                z
[ 0 2 1 ]          l                z
[ 1 0 0 ]          m                z
[ 1 0 0 ]          n                z
[ 1 0 1 ]          p                z
[ 1 0 1 ]          q                z
[ 1 1 0 ]          r                z
[ 1 1 0 ]          s                z
[ 1 1 1 ]          t                z
[ 1 1 1 ]          u                z
[ 1 2 0 ]          v                z
[ 1 2 0 ]          w                z
[ 1 2 1 ]          x                z
[ 2 0 0 ]          A                z
[ 2 0 0 ]          B                z
[ 2 0 1 ]          C                z
[ 2 0 1 ]          D                z
[ 2 1 0 ]          E                z
[ 2 1 0 ]          F                z
[ 2 1 1 ]          G                z
[ 2 1 1 ]          H                z
[ 2 2 0 ]          I                z
[ 2 2 0 ]          J                z
[ 2 2 1 ]          K                z
[ 2 2 1 ]          L                z
[ 3 0 0 ]          M                z
[ 3 0 0 ]          N                z
[ 3 0 1 ]          P                z
[ 3 0 1 ]          Q                z
[ 3 1 0 ]          R                z
[ 3 1 0 ]          S                z
[ 3 1 1 ]          T                z
[ 3 1 1 ]          U                z
[ 3 2 0 ]          V                z
[ 3 2 0 ]          W                z
[ 3 2 1 ]          X                z
[ 3 2 1 ]          Z                z
 */

 tid = H5Tcopy(H5T_C_S1);
 status  = H5Tset_size(tid, 2);
 write_attr(loc_id,3,dims3,"string3D",tid,buf13);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_BITFIELD
 *-------------------------------------------------------------------------
 */

 n=1;
 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    if (make_diffs) buf23[i][j][k]=0;
    else buf23[i][j][k]=n++;
   }
  }
 }

/*
position        bitfield3D of </g1> bitfield3D of </g1> difference
------------------------------------------------------------
[ 0 0 0 ]          1               0               1
[ 0 0 1 ]          2               0               2
[ 0 1 0 ]          3               0               3
[ 0 1 1 ]          4               0               4
[ 0 2 0 ]          5               0               5
[ 0 2 1 ]          6               0               6
[ 1 0 0 ]          7               0               7
[ 1 0 1 ]          8               0               8
[ 1 1 0 ]          9               0               9
[ 1 1 1 ]          10              0               10
[ 1 2 0 ]          11              0               11
[ 1 2 1 ]          12              0               12
[ 2 0 0 ]          13              0               13
[ 2 0 1 ]          14              0               14
[ 2 1 0 ]          15              0               15
[ 2 1 1 ]          16              0               16
[ 2 2 0 ]          17              0               17
[ 2 2 1 ]          18              0               18
[ 3 0 0 ]          19              0               19
[ 3 0 1 ]          20              0               20
[ 3 1 0 ]          21              0               21
[ 3 1 1 ]          22              0               22
[ 3 2 0 ]          23              0               23
[ 3 2 1 ]          24              0               24
*/

 tid = H5Tcopy(H5T_STD_B8LE);
 write_attr(loc_id,3,dims3,"bitfield3D",tid,buf23);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_OPAQUE
 *-------------------------------------------------------------------------
 */
 tid = H5Tcreate(H5T_OPAQUE, 1);
 status = H5Tset_tag(tid, "1-byte opaque type"); /* must set this */
 write_attr(loc_id,3,dims3,"opaque3D",tid,buf23);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_COMPOUND
 *-------------------------------------------------------------------------
 */

 n=1;
 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    if (make_diffs) {
     buf33[i][j][k].a=0;
     buf33[i][j][k].b=0;
    }
    else {
     buf33[i][j][k].a=n++;
     buf33[i][j][k].b=n++;
    }
   }
  }
 }
/*position        compound3D of </g1> compound3D of </g1> difference
------------------------------------------------------------
[ 0 0 0 ]          1               0               1
[ 0 0 0 ]          2               0               2
[ 0 0 1 ]          3               0               3
[ 0 0 1 ]          4               0               4
[ 0 1 0 ]          5               0               5
[ 0 1 0 ]          6               0               6
[ 0 1 1 ]          7               0               7
[ 0 1 1 ]          8               0               8
[ 0 2 0 ]          9               0               9
[ 0 2 0 ]          10              0               10
[ 0 2 1 ]          11              0               11
[ 0 2 1 ]          12              0               12
[ 1 0 0 ]          13              0               13
[ 1 0 0 ]          14              0               14
[ 1 0 1 ]          15              0               15
[ 1 0 1 ]          16              0               16
[ 1 1 0 ]          17              0               17
[ 1 1 0 ]          18              0               18
[ 1 1 1 ]          19              0               19
[ 1 1 1 ]          20              0               20
[ 1 2 0 ]          21              0               21
[ 1 2 0 ]          22              0               22
[ 1 2 1 ]          23              0               23
[ 1 2 1 ]          24              0               24
[ 2 0 0 ]          25              0               25
[ 2 0 0 ]          26              0               26
[ 2 0 1 ]          27              0               27
[ 2 0 1 ]          28              0               28
[ 2 1 0 ]          29              0               29
[ 2 1 0 ]          30              0               30
[ 2 1 1 ]          31              0               31
[ 2 1 1 ]          32              0               32
[ 2 2 0 ]          33              0               33
[ 2 2 0 ]          34              0               34
[ 2 2 1 ]          35              0               35
[ 2 2 1 ]          36              0               36
[ 3 0 0 ]          37              0               37
[ 3 0 0 ]          38              0               38
[ 3 0 1 ]          39              0               39
[ 3 0 1 ]          40              0               40
[ 3 1 0 ]          41              0               41
[ 3 1 0 ]          42              0               42
[ 3 1 1 ]          43              0               43
[ 3 1 1 ]          44              0               44
[ 3 2 0 ]          45              0               45
[ 3 2 0 ]          46              0               46
[ 3 2 1 ]          47              0               47
[ 3 2 1 ]          48              0               48
*/



 tid = H5Tcreate (H5T_COMPOUND, sizeof(s_t));
 H5Tinsert(tid, "a", HOFFSET(s_t, a), H5T_NATIVE_CHAR);
 H5Tinsert(tid, "b", HOFFSET(s_t, b), H5T_NATIVE_DOUBLE);
 write_attr(loc_id,3,dims3,"compound3D",tid,buf33);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_REFERENCE (H5R_OBJECT object reference)
 *-------------------------------------------------------------------------
 */
 /* Create references to dataset */
 if (dset_name)
 {
  for (i = 0; i < 4; i++) {
   for (j = 0; j < 3; j++) {
    for (k = 0; k < 2; k++)
     status=H5Rcreate(&buf43[i][j][k],fid,dset_name,H5R_OBJECT,-1);
   }
  }
 write_attr(loc_id,3,dims3,"reference3D",H5T_STD_REF_OBJ,buf43);
 }

/*-------------------------------------------------------------------------
 * H5T_ENUM
 *-------------------------------------------------------------------------
 */

 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    if (make_diffs) buf453[i][j][k]=RED; else buf453[i][j][k]=GREEN;
   }
  }
 }

/*
position        enum3D of </g1> enum3D of </g1> difference
------------------------------------------------------------
[ 0 0 0 ]          GREEN            RED
[ 0 0 1 ]          GREEN            RED
[ 0 1 0 ]          GREEN            RED
[ 0 1 1 ]          GREEN            RED
[ 0 2 0 ]          GREEN            RED
[ 0 2 1 ]          GREEN            RED
[ 1 0 0 ]          GREEN            RED
[ 1 0 1 ]          GREEN            RED
[ 1 1 0 ]          GREEN            RED
[ 1 1 1 ]          GREEN            RED
[ 1 2 0 ]          GREEN            RED
[ 1 2 1 ]          GREEN            RED
[ 2 0 0 ]          GREEN            RED
[ 2 0 1 ]          GREEN            RED
[ 2 1 0 ]          GREEN            RED
[ 2 1 1 ]          GREEN            RED
[ 2 2 0 ]          GREEN            RED
[ 2 2 1 ]          GREEN            RED
[ 3 0 0 ]          GREEN            RED
[ 3 0 1 ]          GREEN            RED
[ 3 1 0 ]          GREEN            RED
[ 3 1 1 ]          GREEN            RED
[ 3 2 0 ]          GREEN            RED
[ 3 2 1 ]          GREEN            RED
*/


 tid = H5Tcreate(H5T_ENUM, sizeof(e_t));
 H5Tenum_insert(tid, "RED",   (val = 0, &val));
 H5Tenum_insert(tid, "GREEN", (val = 1, &val));
 write_attr(loc_id,3,dims3,"enum3D",tid,buf453);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_VLEN
 *-------------------------------------------------------------------------
 */

 /* Allocate and initialize VL dataset to write */
 n=0;
 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    int l;
    buf53[i][j][k].p = malloc((i + 1) * sizeof(int));
    buf53[i][j][k].len = i + 1;
    for (l = 0; l < i + 1; l++)
    if (make_diffs)((int *)buf53[i][j][k].p)[l] = 0;
    else ((int *)buf53[i][j][k].p)[l] = n++;
   }
  }
 }
/*
position        vlen3D of </g1> vlen3D of </g1> difference
------------------------------------------------------------
[ 0 0 1 ]          1               0               1
[ 0 1 0 ]          2               0               2
[ 0 1 1 ]          3               0               3
[ 0 2 0 ]          4               0               4
[ 0 2 1 ]          5               0               5
[ 1 0 0 ]          6               0               6
[ 1 0 0 ]          7               0               7
[ 1 0 1 ]          8               0               8
[ 1 0 1 ]          9               0               9
[ 1 1 0 ]          10              0               10
etc
*/
 sid = H5Screate_simple(3,dims3,NULL);
 tid = H5Tvlen_create(H5T_NATIVE_INT);
 aid = H5Acreate(loc_id,"vlen3D",tid,sid,H5P_DEFAULT);
 status = H5Awrite(aid,tid,buf53);
 assert(status>=0);
 status = H5Dvlen_reclaim(tid,sid,H5P_DEFAULT,buf53);
 assert(status>=0);
 status = H5Aclose(aid);
 status = H5Tclose(tid);
 status = H5Sclose(sid);

/*-------------------------------------------------------------------------
 * H5T_ARRAY
 *-------------------------------------------------------------------------
 */
 n=1;
 for (i = 0; i < 24; i++) {
  for (j = 0; j < (int)dimarray[0]; j++) {
    if (make_diffs) buf63[i][j]=0;
    else buf63[i][j]=n++;
  }
 }
 /*
 position        array3D of </g1> array3D of </g1> difference
------------------------------------------------------------
[ 0 0 0 ]          1               0               1
[ 0 0 0 ]          2               0               2
[ 0 0 0 ]          3               0               3
[ 0 0 1 ]          4               0               4
[ 0 0 1 ]          5               0               5
[ 0 0 1 ]          6               0               6
[ 0 1 0 ]          7               0               7
etc
*/

 tid = H5Tarray_create(H5T_NATIVE_INT,1,dimarray,NULL);
 write_attr(loc_id,3,dims3,"array3D",tid,buf63);
 status = H5Tclose(tid);

/*-------------------------------------------------------------------------
 * H5T_INTEGER and H5T_FLOAT
 *-------------------------------------------------------------------------
 */
 n=1; f=1;
 for (i = 0; i < 4; i++) {
  for (j = 0; j < 3; j++) {
   for (k = 0; k < 2; k++) {
    if (make_diffs) {
     buf73[i][j][k]=0;
     buf83[i][j][k]=0;
    }
    else {
     buf73[i][j][k]=n++;
     buf83[i][j][k]=f++;
    }
   }
  }
 }

 /*
 position        integer3D of </g1> integer3D of </g1> difference
------------------------------------------------------------
[ 0 0 0 ]          1               0               1
[ 0 0 1 ]          2               0               2
[ 0 1 0 ]          3               0               3
[ 0 1 1 ]          4               0               4
[ 0 2 0 ]          5               0               5
[ 0 2 1 ]          6               0               6
[ 1 0 0 ]          7               0               7
[ 1 0 1 ]          8               0               8
[ 1 1 0 ]          9               0               9
[ 1 1 1 ]          10              0               10
etc
*/
 write_attr(loc_id,3,dims3,"integer3D",H5T_NATIVE_INT,buf73);
 write_attr(loc_id,3,dims3,"float3D",H5T_NATIVE_FLOAT,buf83);
}

/*-------------------------------------------------------------------------
 * Function: test_dsetall
 *
 * Purpose: Check all HDF5 classes
 * H5T_INTEGER, H5T_FLOAT
 * H5T_TIME, H5T_STRING, H5T_BITFIELD, H5T_OPAQUE, H5T_COMPOUND, H5T_REFERENCE,
 * H5T_ENUM, H5T_VLEN, H5T_ARRAY
 *
 *-------------------------------------------------------------------------
 */
static
int test_dsetall(const char *file,
                 int make_diffs /* flag to modify data buffers */)
{
 hid_t   fid;
 hid_t   did;
 hid_t   gid;
 hid_t   sid;
 hsize_t dims[1]={2};
 herr_t  status;
 int     buf[2]={1,2};

 if (make_diffs)
 {
  memset(buf,0,sizeof buf);
 }

 /* Create a file  */
 if ((fid  = H5Fcreate(file, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT))<0)
  return -1;

 /* Create a 1D dataset */
 sid = H5Screate_simple(1,dims,NULL);
 did  = H5Dcreate(fid,"dset",H5T_NATIVE_INT,sid,H5P_DEFAULT);
 status   = H5Dwrite(did,H5T_NATIVE_INT,H5S_ALL,H5S_ALL,H5P_DEFAULT,buf);
 status   = H5Sclose(sid);
 assert(status>=0);

 /* Create a group */
 gid  = H5Gcreate(fid,"g1",0);

/*-------------------------------------------------------------------------
 * write a series of datasets on the group
 *-------------------------------------------------------------------------
 */

 write_dset_in(gid,"/dset",fid,make_diffs);

 /* Close */
 status = H5Dclose(did);
 assert(status>=0);
 status = H5Gclose(gid);
 assert(status>=0);

 /* Close file */
 status = H5Fclose(fid);
 assert(status>=0);
 return status;
}

/*-------------------------------------------------------------------------
 * Function: test_basic
 *
 * Purpose: Basic review tests
 *
 *-------------------------------------------------------------------------
 */
static
int test_basic(const char *file1, 
               const char *file2)
{

 hid_t   fid1, fid2;
 hid_t   gid1, gid2, gid3;
 herr_t  status;
 hsize_t dims[2] = { 3,2 };

 /* Test */
 double  data1[3][2] = {{1,1},{1,1},{1,1}};
 double  data2[3][2] = {{1,1.1},{1.01,1.001},{1.0001,1}};
 double  data3[3][2] = {{100,110},{100,100},{100,100}};
 double  data4[3][2] = {{110,100},{90,80},{140,200}};
 int     data5[3][2] = {{100,100},{100,100},{100,100}};
 int     data6[3][2] = {{101,102},{103,104},{150,200}};
 unsigned long_long data7[3][2] = {{100,100},{100,100},{100,100}};
 unsigned long_long data8[3][2] = {{101,102},{103,104},{150,200}};

/*-------------------------------------------------------------------------
 * Create two files
 *-------------------------------------------------------------------------
 */

 fid1 = H5Fcreate (file1, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
 fid2 = H5Fcreate (file2, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

 /* Create groups */
 gid1 = H5Gcreate(fid1, "g1", 0);
 gid2 = H5Gcreate(fid2, "g1", 0);
 gid3 = H5Gcreate(fid2, "g2", 0);

 write_dset(gid1,2,dims,"dset1",H5T_NATIVE_DOUBLE,data1);
 write_dset(gid2,2,dims,"dset2",H5T_NATIVE_DOUBLE,data2);
 write_dset(gid1,2,dims,"dset3",H5T_NATIVE_DOUBLE,data3);
 write_dset(gid2,2,dims,"dset4",H5T_NATIVE_DOUBLE,data4);
 write_dset(gid2,2,dims,"dset1",H5T_NATIVE_DOUBLE,data2);

 /* relative (int) */
 write_dset(gid1,2,dims,"dset5",H5T_NATIVE_INT,data5);
 write_dset(gid1,2,dims,"dset6",H5T_NATIVE_INT,data6);
 /* relative (unsigned long_long) */
 write_dset(gid1,2,dims,"dset7",H5T_NATIVE_ULLONG,data7);
 write_dset(gid1,2,dims,"dset8",H5T_NATIVE_ULLONG,data8);

/*-------------------------------------------------------------------------
 * Close
 *-------------------------------------------------------------------------
 */
 status = H5Gclose(gid1);
 status = H5Gclose(gid2);
 status = H5Gclose(gid3);
 status = H5Fclose(fid1);
 status = H5Fclose(fid2);
 return status;
}

/*-------------------------------------------------------------------------
 * Function: test_basic
 *
 * Purpose: Compare different HDF5 types (H5G_obj_t): 
 * H5G_DATASET, H5G_TYPE, H5G_GROUP, H5G_LINK
 *
 *-------------------------------------------------------------------------
 */
static
int test_types(const char *file1, 
               const char UNUSED *file2)
{

 hid_t   fid1;
 hid_t   gid1;
 hid_t   gid2;
 hid_t   tid1;
 hid_t   tid2;
 herr_t  status;
 hsize_t dims[1]={1};
 typedef struct s1_t
 {
  int    a;
  float  b;
 } s1_t;
 typedef struct s2_t
 {
  int    a;
 } s2_t;

/*-------------------------------------------------------------------------
 * Create one file
 *-------------------------------------------------------------------------
 */
 fid1 = H5Fcreate (file1, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

/*-------------------------------------------------------------------------
 * H5G_DATASET
 *-------------------------------------------------------------------------
 */
 write_dset(fid1,1,dims,"dset",H5T_NATIVE_INT,0);

/*-------------------------------------------------------------------------
 * H5G_GROUP
 *-------------------------------------------------------------------------
 */
 gid1 = H5Gcreate(fid1, "g1", 0);
 status = H5Gclose(gid1);
 gid2 = H5Gcreate(fid1, "g2", 0);
 status = H5Gclose(gid2);

/*-------------------------------------------------------------------------
 * H5G_TYPE
 *-------------------------------------------------------------------------
 */

 /* create and commit datatype 1 */
 tid1 = H5Tcreate (H5T_COMPOUND, sizeof(s1_t));
 H5Tinsert(tid1, "a", HOFFSET(s1_t, a), H5T_NATIVE_INT);
 H5Tinsert(tid1, "b", HOFFSET(s1_t, b), H5T_NATIVE_FLOAT);
 H5Tcommit(fid1, "t1", tid1);
 H5Tclose(tid1);
 /* create and commit datatype 2 */
 tid2 = H5Tcreate (H5T_COMPOUND, sizeof(s2_t));
 H5Tinsert(tid2, "a", HOFFSET(s2_t, a), H5T_NATIVE_INT);
 H5Tcommit(fid1, "t2", tid2);
 H5Tclose(tid2);

/*-------------------------------------------------------------------------
 * H5G_LINK
 *-------------------------------------------------------------------------
 */

 status = H5Glink(fid1, H5G_LINK_SOFT, "g1", "l1");
 status = H5Glink(fid1, H5G_LINK_SOFT, "g2", "l2");

/*-------------------------------------------------------------------------
 * Close
 *-------------------------------------------------------------------------
 */
 status = H5Fclose(fid1);
 return status;
}

/*-------------------------------------------------------------------------
 * Function: test_native
 *
 * Purpose: test datasets datatypes
 *
 *-------------------------------------------------------------------------
 */
static
int test_native(const char *file1, 
                const char UNUSED *file2)
{

 hid_t   fid1;
 hsize_t dims[2]={3,2};
 herr_t  status;
 char    buf1a[3][2] = {{1,1},{1,1},{1,1}};
 char    buf1b[3][2] = {{1,1},{3,4},{5,6}};
 short   buf2a[3][2] = {{1,1},{1,1},{1,1}};
 short   buf2b[3][2] = {{1,1},{3,4},{5,6}};
 int     buf3a[3][2] = {{1,1},{1,1},{1,1}};
 int     buf3b[3][2] = {{1,1},{3,4},{5,6}};
 long    buf4a[3][2] = {{1,1},{1,1},{1,1}};
 long    buf4b[3][2] = {{1,1},{3,4},{5,6}};
 float   buf5a[3][2] = {{1,1},{1,1},{1,1}};
 float   buf5b[3][2] = {{1,1},{3,4},{5,6}};
 double  buf6a[3][2] = {{1,1},{1,1},{1,1}};
 double  buf6b[3][2] = {{1,1},{3,4},{5,6}};

 /*unsigned/signed test
   signed char -128 to 127
   unsigned char 0 to 255
  */
 char          buf7a[3][2] = {{-1,-128},{-1,-1},{-1,-1}};
 unsigned char buf7b[3][2] = {{1,128},{1,1},{1,1}};

 /* long_long test */
 long_long            buf8a[3][2] = {{1,1},{1,1},{1,1}};
 long_long            buf8b[3][2] = {{1,1},{3,4},{5,6}};
 unsigned long_long   buf9a[3][2] = {{1,1},{1,1},{1,1}};
 unsigned long_long   buf9b[3][2] = {{1,1},{3,4},{5,6}};

 unsigned int    buf10a[3][2] = {{UIMAX,1},{1,1},{1,1}};
 unsigned int    buf10b[3][2] = {{UIMAX-1,1},{3,4},{5,6}};


/*-------------------------------------------------------------------------
 * Create a file
 *-------------------------------------------------------------------------
 */
 fid1 = H5Fcreate (file1, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

/*-------------------------------------------------------------------------
 * Check for different storage order. Give a warning if they are different
 *-------------------------------------------------------------------------
 */

 write_dset(fid1,2,dims,"dset0a",H5T_STD_I16LE,buf2a);
 write_dset(fid1,2,dims,"dset0b",H5T_STD_I32LE,buf3b);

/*-------------------------------------------------------------------------
 * Check H5T_NATIVE_CHAR
 *-------------------------------------------------------------------------
 */
 write_dset(fid1,2,dims,"dset1a",H5T_NATIVE_CHAR,buf1a);
 write_dset(fid1,2,dims,"dset1b",H5T_NATIVE_CHAR,buf1b);

/*-------------------------------------------------------------------------
 * Check H5T_NATIVE_SHORT
 *-------------------------------------------------------------------------
 */
 write_dset(fid1,2,dims,"dset2a",H5T_NATIVE_SHORT,buf2a);
 write_dset(fid1,2,dims,"dset2b",H5T_NATIVE_SHORT,buf2b);

/*-------------------------------------------------------------------------
 * Check H5T_NATIVE_INT
 *-------------------------------------------------------------------------
 */
 write_dset(fid1,2,dims,"dset3a",H5T_NATIVE_INT,buf3a);
 write_dset(fid1,2,dims,"dset3b",H5T_NATIVE_INT,buf3b);

/*-------------------------------------------------------------------------
 * Check H5T_NATIVE_LONG
 *-------------------------------------------------------------------------
 */
 write_dset(fid1,2,dims,"dset4a",H5T_NATIVE_LONG,buf4a);
 write_dset(fid1,2,dims,"dset4b",H5T_NATIVE_LONG,buf4b);

/*-------------------------------------------------------------------------
 * Check H5T_NATIVE_FLOAT
 *-------------------------------------------------------------------------
 */
 write_dset(fid1,2,dims,"dset5a",H5T_NATIVE_FLOAT,buf5a);
 write_dset(fid1,2,dims,"dset5b",H5T_NATIVE_FLOAT,buf5b);

/*-------------------------------------------------------------------------
 * Check H5T_NATIVE_DOUBLE
 *-------------------------------------------------------------------------
 */

 write_dset(fid1,2,dims,"dset6a",H5T_NATIVE_DOUBLE,buf6a);
 write_dset(fid1,2,dims,"dset6b",H5T_NATIVE_DOUBLE,buf6b);

/*-------------------------------------------------------------------------
 * H5T_NATIVE_CHAR and H5T_NATIVE_UCHAR
 *-------------------------------------------------------------------------
 */

 write_dset(fid1,2,dims,"dset7a",H5T_NATIVE_CHAR,buf7a);
 write_dset(fid1,2,dims,"dset7b",H5T_NATIVE_UCHAR,buf7b);

/*-------------------------------------------------------------------------
 * H5T_NATIVE_LLONG
 *-------------------------------------------------------------------------
 */

 write_dset(fid1,2,dims,"dset8a",H5T_NATIVE_LLONG,buf8a);
 write_dset(fid1,2,dims,"dset8b",H5T_NATIVE_LLONG,buf8b);

/*-------------------------------------------------------------------------
 * H5T_NATIVE_ULLONG
 *-------------------------------------------------------------------------
 */

 write_dset(fid1,2,dims,"dset9a",H5T_NATIVE_ULLONG,buf9a);
 write_dset(fid1,2,dims,"dset9b",H5T_NATIVE_ULLONG,buf9b);

/*-------------------------------------------------------------------------
 * H5T_NATIVE_INT
 *-------------------------------------------------------------------------
 */

 write_dset(fid1,2,dims,"dset10a",H5T_NATIVE_UINT,buf10a);
 write_dset(fid1,2,dims,"dset10b",H5T_NATIVE_UINT,buf10b);


/*-------------------------------------------------------------------------
 * Close
 *-------------------------------------------------------------------------
 */
 status = H5Fclose(fid1);
 return status;
}

/*-------------------------------------------------------------------------
 * Function: test_attr
 *
 * Purpose: test attributes
 *
 *-------------------------------------------------------------------------
 */
static
int test_attr(const char *file,
              int make_diffs /* flag to modify data buffers */)
{
 hid_t   fid;
 hid_t   did;
 hid_t   gid;
 hid_t   root_id;
 hid_t   sid;
 hsize_t dims[1]={2};
 herr_t  status;

 /* Create a file  */
 if ((fid  = H5Fcreate(file, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT))<0)
  return -1;

 /* Create a 1D dataset */
 sid = H5Screate_simple(1,dims,NULL);
 did  = H5Dcreate(fid,"dset",H5T_NATIVE_INT,sid,H5P_DEFAULT);
 status   = H5Sclose(sid);
 assert(status>=0);

 /* Create groups */
 gid  = H5Gcreate(fid,"g1",0);
 root_id   = H5Gopen(fid, "/");

/*-------------------------------------------------------------------------
 * write a series of attributes on the dataset, group, and root group
 *-------------------------------------------------------------------------
 */

 write_attr_in(did,"dset",fid,make_diffs);
 write_attr_in(gid,NULL,0,make_diffs);
 write_attr_in(root_id,NULL,0,make_diffs);


 /* Close */
 status = H5Dclose(did);
 assert(status>=0);
 status = H5Gclose(gid);
 assert(status>=0);
 status = H5Gclose(root_id);
 assert(status>=0);

 /* Close file */
 status = H5Fclose(fid);
 assert(status>=0);
 return status;
}


/*-------------------------------------------------------------------------
 * Function: main
 *
 * Purpose: main program
 *
 *-------------------------------------------------------------------------
 */

int main(int UNUSED argc, const UNUSED char *argv[])
{

 test_basic (FILE1,FILE2);
 test_types (FILE3,NULL);
 test_native(FILE4,NULL);

 /* generate 2 files with attribute differences */
 test_attr(FILE5,0);
 test_attr(FILE6,1);

 /* generate 2 files with all datatype differences */
 test_dsetall(FILE7,0);
 test_dsetall(FILE8,1);
 return 0;
}
