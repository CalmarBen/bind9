/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/util.h>

#include "mutex_p.h"

pthread_mutexattr_t isc__mutex_init_attr;
static isc_once_t init_once = ISC_ONCE_INIT;

static void
mutex_initialize(void) {
	RUNTIME_CHECK(pthread_mutexattr_init(&isc__mutex_init_attr) == 0);
#ifdef HAVE_PTHREAD_MUTEX_ADAPTIVE_NP
	RUNTIME_CHECK(pthread_mutexattr_settype(&isc__mutex_init_attr,
						PTHREAD_MUTEX_ADAPTIVE_NP) ==
		      0);
#endif /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */
}

void
isc__mutex_initialize(void) {
	isc_once_do(&init_once, mutex_initialize);
}

void
isc__mutex_shutdown(void) {
	/* noop */;
}
