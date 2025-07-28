##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
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
AM_CXXFLAGS = -std=c++11
AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = service_wan_gtest.bin
service_wan_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
                        -I$(top_srcdir)/source \
                        -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/dbus-1.0 \
                        -I${PKG_CONFIG_SYSROOT_DIR}$(libdir)/dbus-1.0/include \
                        -DUNIT_TEST_DOCKER_SUPPORT

service_wan_gtest_bin_SOURCES = $(top_builddir)/source/service_wan/service_wan.c \
                                   service_wan_mock.cpp \
                                   service_wan_mock.h \
                                   gtest_main.cpp

service_wan_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_ccsp_common.la \
                               $(HOME)/usr/local/lib/libmock_secure_wrapper.la \
                               $(HOME)/usr/local/lib/libmock_safec_lib.la \
                               $(HOME)/usr/local/lib/libmock_syscfg.la \
                               $(HOME)/usr/local/lib/libmock_base64.la \
                               $(HOME)/usr/local/lib/libmock_webconfigframework.la \
                               $(HOME)/usr/local/lib/libmock_msgpack.la \
                               $(HOME)/usr/local/lib/libmock_sysevent.la \
                               $(HOME)/usr/local/lib/libmock_utopia.la  \
                               $(HOME)/usr/local/lib/libmock_telemetry.la \
                               $(HOME)/usr/local/lib/libmock_psm.la \
                               $(HOME)/usr/local/lib/libmock_file_io.la \
                               $(HOME)/usr/local/lib/libmock_ccsp_common.la \
                               $(HOME)/usr/local/lib/libmock_rdklogger.la

service_wan_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -pthread
#Code Coverage Flags
AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
service_wan_gtest_bin_LDFLAGS += --coverage