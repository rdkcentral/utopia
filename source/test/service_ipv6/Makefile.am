##########################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

AM_CFLAGS =
AM_CPPFLAGS =  -Wall -g -Werror
AM_CXXFLAGS = -std=c++11
ACLOCAL_AMFLAGS = -I m4
AUTOMAKES_OPTIONS = subdir-objects
bin_PROGRAMS = service_ipv6_gtest.bin

service_ipv6_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
                                  -I${top_srcdur}/source \
				  -I${top_srcdir}/source/util/utils \
                                  -I${top_srcdir}/source/service_ipv6 \
				  -D_BWG_PRODUCT_REQ_ \
                                  -DUNIT_TEST_DOCKER_SUPPORT \
				  -DCORE_NET_LIB

service_ipv6_gtest_bin_SOURCES  = ${top_srcdir}/source/service_ipv6/service_ipv6.c \
				  service_ipv6_test.cpp \
				  service_ipv6_mock.cpp \
                                  gtest_main.cpp

service_ipv6_gtest_bin_LDFLAGS  = -lgtest -lgmock -lgcov -lpthread

service_ipv6_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_rbus.la \
                               $(HOME)/usr/local/lib/libmock_sysevent.la \
			       $(HOME)/usr/local/lib/libmock_syscfg.la \
			       $(HOME)/usr/local/lib/libmock_utopia.la \
			       $(HOME)/usr/local/lib/libmock_safec_lib.la \
			       $(HOME)/usr/local/lib/libmock_ccsp_common.la \
			       $(HOME)/usr/local/lib/libmock_secure_wrapper.la \
			       $(HOME)/usr/local/lib/libmock_util.la \
			       $(HOME)/usr/local/lib/libmock_psm.la \
			       $(HOME)/usr/local/lib/libmock_libnet.la

#code coverage flags
AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
service_ipv6_gtest_bin_LDFLAGS += --coverage
