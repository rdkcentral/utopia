##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2026 RDK Management
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
AM_CFLAGS = -Wall -Werror

bin_PROGRAMS = stackmode

stackmode_SOURCES = stackmode.c stackmode_log.c

stackmode_CPPFLAGS = -I$(top_srcdir)/source/scripts/init/src/stackmode \
                     -I$(top_srcdir)/source/syscfg \
                     -I$(top_srcdir)/source/include

stackmode_LDADD = $(top_builddir)/source/syscfg/lib/libsyscfg.la \
                  -lhal_platform \
                  -lpthread
