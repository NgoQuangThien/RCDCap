FIND_PACKAGE(Boost 1.47 COMPONENTS unit_test_framework REQUIRED)

INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR}
                    ${LIBPCAP_INCLUDE_DIR}
                    ${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_BINARY_DIR}/include)

IF(NOT WIN32)
	ADD_DEFINITIONS(-DBOOST_TEST_DYN_LINK) 
ENDIF()

ADD_EXECUTABLE(AddressConversionTest address-conversion.cc)

TARGET_LINK_LIBRARIES(AddressConversionTest rcdcap_core ${Boost_LIBRARIES})

ADD_TEST(AddressConversionTest AddressConversionTest)

ADD_EXECUTABLE(ByteSwapTest byte-swap-test.cc)

TARGET_LINK_LIBRARIES(ByteSwapTest rcdcap_core ${Boost_LIBRARIES})

ADD_TEST(ByteSwapTest ByteSwapTest)

ADD_EXECUTABLE(CommonBufferTest common-buffer-test.cc)

TARGET_LINK_LIBRARIES(CommonBufferTest rcdcap_core ${Boost_LIBRARIES})

ADD_TEST(CommonBufferTest CommonBufferTest)

ADD_CUSTOM_TARGET(CopyRCDCapCore
                  COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:rcdcap_core> ${CMAKE_CURRENT_BINARY_DIR}/$<CONFIGURATION>)

ADD_DEPENDENCIES(CommonBufferTest CopyRCDCapCore)

MESSAGE(${LIBPCAP_LIBRARY})