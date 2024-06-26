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

#ifndef mod_authz_ts_cap_ts_whois_h
#define mod_authz_ts_cap_ts_whois_h

#define TS_CAP_MAXLEN      127

apr_status_t ts_whois_get(apr_array_header_t *caps, request_rec *r, const char *uds_path);

#endif