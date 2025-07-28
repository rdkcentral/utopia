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
AM_CFLAGS = -fPIC -fno-exceptions -Os -Wall -Wextra

AM_CXXFLAGS = -std=c++11

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = service_dhcp_gtest.bin

service_dhcp_gtest_bin_CPPFLAGS = \
                        -I$(top_srcdir)/source/service_dhcp/include \
                        -I$(top_srcdir)/source/util/utils \
                        -I$(top_srcdir)/source/util/print_uptime \
                        -DUNIT_TEST_DOCKER_SUPPORT

service_dhcp_gtest_bin_SOURCES =  \
                                  FopenMock.cpp \
                                  service_dhcp_mock.cpp \
                                  service_dhcp_test.cpp \
                                  service_dhcp_server_test.cpp \
                                  service_dhcp_server_function_test.cpp \
                                  service_ipv4_test.cpp \
                                  lan_handler_test.cpp \
                                  $(top_builddir)/source/service_dhcp/dhcp_server_functions.c \
                                  $(top_builddir)/source/service_dhcp/lan_handler.c \
                                  $(top_builddir)/source/service_dhcp/service_dhcp.c \
                                  $(top_builddir)/source/service_dhcp/service_dhcp_server.c \
                                  $(top_builddir)/source/service_dhcp/service_ipv4.c \
                                  gtest_main.cpp


service_dhcp_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_ccsp_common.la \
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
                               $(HOME)/usr/local/lib/libmock_libnet.la \
                               $(HOME)/usr/local/lib/libmock_file_io.la

service_dhcp_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -pthread

#Code Coverage Flags
AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage