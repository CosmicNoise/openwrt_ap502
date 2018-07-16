#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(beacon, 1.0, gerrit_4_me@126.com)
AC_CONFIG_SRCDIR([src/capture.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE
# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(pcap, pcap_open_live, ,AC_MSG_ERROR(You need the pcap library))
AC_CHECK_LIB(crypto, AES_cbc_encrypt, ,AC_MSG_ERROR(You need the crypto library))
AC_CHECK_LIB(ssl, DSA_get_default_method, ,AC_MSG_ERROR(You need the ssl library))
AC_CHECK_LIB(nl-tiny, nl_socket_alloc, , AC_MSG_ERROR(You need the libnl-3 library))
#AC_CHECK_LIB(nl-genl-3, genl_ctrl_resolve, , AC_MSG_ERROR(You need the libnl-genl-3 library))

# Checks for header files.

#AM_MAKE_INCLUDE(/usr/include/libnl3/)
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdlib.h string.h sys/ioctl.h sys/time.h syslog.h unistd.h netlink/genl/genl.h \ 
		linux/if_slip.h netinet/in.h netlink/msg.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset regcomp socket strerror strndup pcap_open_live])

AC_OUTPUT(Makefile)
