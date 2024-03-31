# Copyright 2022 Stefan Eissing (<stefan@eissing.org>)
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
#

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = mod_authz_ts_cap.la

#---------------------------------------------------------------------------------------------------
# mod_authz_ts_cap for httpd
#---------------------------------------------------------------------------------------------------

mod_authz_ts_cap_la_CPPFLAGS = -g -I../src -std=c99 -D_GNU_SOURCE @WERROR_CFLAGS@
mod_authz_ts_cap_la_LDFLAGS  = -module -ljansson -lcurl -export-symbols-regex authz_ts_cap_module


OBJECTS = \
    mod_authz_ts_cap.c \
    ts_whois.c

HFILES = \
	mod_authz_ts_cap.h \
    ts_whois.h

mod_authz_ts_cap_la_SOURCES = $(HFILES) $(OBJECTS)

all: mod_authz_ts_cap.la

#---------------------------------------------------------------------------------------------------
# installations
#---------------------------------------------------------------------------------------------------

install-exec-local: mod_authz_ts_cap.la
	$(MKDIR_P) $(DESTDIR)/@LIBEXEC_DIR@
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)/@LIBEXEC_DIR@ -n md mod_authz_ts_cap.la
