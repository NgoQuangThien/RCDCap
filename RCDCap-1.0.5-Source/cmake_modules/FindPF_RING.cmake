FIND_PATH(LIBPFRING_INCLUDE_DIR NAMES "pfring.h" PATH_SUFFIXES "include" "local/include")
IF(PFRING_STATIC)
	SET(PFRING_LIB_NAME "libpfring.a")	
ELSE()
	SET(PFRING_LIB_NAME "pfring")
ENDIF()
FIND_LIBRARY(LIBPFRING_LIBRARY NAMES "${PFRING_LIB_NAME}" PATH_SUFFIXES "lib" "local/lib")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBPFRING DEFAULT_MSG LIBPFRING_LIBRARY LIBPFRING_INCLUDE_DIR)

IF(LIBPFRING_INCLUDE_DIR AND LIBPFRING_LIBRARY)
	MARK_AS_ADVANCED(LIBPFRING_INCLUDE_DIR LIBPFRING_LIBRARY)
ENDIF()
