SET(CPACK_GENERATOR ${CPACK_GENERATOR} "RPM")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "RCDCap is a remote capture preprocessor.")
SET(CPACK_PACKAGE_DESCRIPTION "RCDCap is a remote capture preprocessor. It is used for removing some types of encapsulation from the incoming traffic, such as HP ERM and CISCO ERSPAN. That makes it particularly suitable for adapting the traffic for applications that do not support this kind of encapsulation.")
IF(NOT RCDCAP_NODEPS AND NOT RCDCAP_STATIC)
	SET(CPACK_RPM_PACKAGE_REQUIRES "boost libpcap")
ENDIF()
SET(CPACK_RPM_PACKAGE_HOMEPAGE "http://sourceforge.net/projects/rcdcap")
SET(CPACK_RPM_PACKAGE_GROUP "RCDCap")
SET(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
#SET(CPACK_RPM_CHANGELOG_FILE "${CMAKE_SOURCE_DIR}/ChangeLog.txt")
SET(CPACK_RPM_SPEC_INSTALL_POST "/bin/true")