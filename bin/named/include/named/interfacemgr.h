/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef NS_INTERFACEMGR_H
#define NS_INTERFACEMGR_H 1

/*****
 ***** Module Info
 *****/

/*
 * Interface manager
 *
 * The interface manager monitors the operating system's list 
 * of network interfaces, creating and destroying listeners 
 * as needed.
 *
 * Reliability:
 *	No impact expected.
 *
 * Resources:
 *
 * Security:
 * 	The server will only be able to bind to the DNS port on
 *	newly discovered interfaces if it is running as root.
 *
 * Standards:
 *	The API for scanning varies greatly among operating systems.
 *	This module attempts to hide the differences.
 */

/***
 *** Imports
 ***/

#include <isc/types.h>
#include <isc/result.h>
#include <isc/mem.h>
#include <isc/socket.h>

#include <dns/result.h>

#include <named/types.h>

/***
 *** Types
 ***/

typedef struct ns_interfacemgr ns_interfacemgr_t;

/***
 *** Functions
 ***/

isc_result_t
ns_interfacemgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		       isc_socketmgr_t *socketmgr, ns_clientmgr_t *clientmgr,
		       ns_interfacemgr_t **mgrp);

void
ns_interfacemgr_scan(ns_interfacemgr_t *mgr);
/*
 * Scan the operatings system's list of network interfaces
 * and create listeners when new interfaces are discovered.
 * Shut down the sockets for interfaces that go away.
 *
 * XXX should honor the listen-on directive in named.conf.
 *
 * This should be called once on server startup and then
 * periodically according to the 'interface-interval' option
 * in named.conf.
 */

void
ns_interfacemgr_destroy(ns_interfacemgr_t **mgrp);
/*
 * Destroy the interface manager.  
 */

#endif /* NS_INTERFACEMGR_H */
