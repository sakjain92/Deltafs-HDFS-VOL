#############################
Expected output for 'h5dump -H --sort_by=name --sort_order=ascending torderattr.h5'
#############################
HDF5 "torderattr.h5" {
GROUP "/" {
   DATASET "dset" {
      DATATYPE  H5T_STD_U8LE
      DATASPACE  SCALAR
      ATTRIBUTE "a" {
         DATATYPE  H5T_STD_U8LE
         DATASPACE  SCALAR
      }
      ATTRIBUTE "b" {
         DATATYPE  H5T_STD_U8LE
         DATASPACE  SCALAR
      }
      ATTRIBUTE "c" {
         DATATYPE  H5T_STD_U8LE
         DATASPACE  SCALAR
      }
   }
   GROUP "g" {
      ATTRIBUTE "a" {
         DATATYPE  H5T_STD_U8LE
         DATASPACE  SCALAR
      }
      ATTRIBUTE "b" {
         DATATYPE  H5T_STD_U8LE
         DATASPACE  SCALAR
      }
      ATTRIBUTE "c" {
         DATATYPE  H5T_STD_U8LE
         DATASPACE  SCALAR
      }
   }
}
}