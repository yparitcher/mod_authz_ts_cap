/***************************************************************************
 *                                  _   _ ____  _
 * Copyright (C) 2022, Stefan Eissing, <stefan@eissing.org>, et al.
 * Copyright (C) 2024, Y Paritcher <y@paritcher.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#ifndef mod_authz_ts_cap_h
#define mod_authz_ts_cap_h

#undef PACKAGE_VERSION
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT

/**
 * @macro
 * Version number of the md module as c string
 */
#define MOD_AUTHZ_TS_CAP_VERSION "0.0.1-git"

/* user agent for requests */
#define MOD_AUTHZ_TS_CAP_UA      "Apache mod_authz_ts_cap "##MOD_AUTHZ_TS_CAP_VERSION

/**
 * @macro
 * Numerical representation of the version number of the module
 * release. This is a 24 bit number with 8 bits for major number, 8 bits
 * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
 */
#define MOD_AUTHZ_TS_CAP_VERSION_NUM 0x000001

#define TAILSCALE_DEF_URL    "/var/run/tailscale/tailscaled.sock"

#endif /* mod_authz_ts_cap_h */
