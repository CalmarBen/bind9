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

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/buffer.h>

#include <isc/task.h>


#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>
#include <isccfg/grammar.h>

#include <ns/hooks.h>
#include <ns/log.h>

#if HAVE_LIBNFTNL
#if HAVE_LIBIPSET
/* <linux/netfilter.h> and <libipset/types.h> are conflicting
 * but we need those two missing defs */
#define NFPROTO_INET    1
#define NFPROTO_NETDEV  5
#else  /* if HAVE_LIBIPSET */
#include <linux/netfilter.h>
#endif /* if HAVE_LIBIPSET */
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/set.h>
#endif /* if HAVE_LIBNFTNL */
#if HAVE_LIBIPSET
#include <libipset/types.h>
#include <libipset/session.h>
#endif /* if HAVE_LIBIPSET */

#define IPSET_INST_MAGIC         ISC_MAGIC('I', 'P', 'S', 'i')
#define VALID_IPSET_INST(c) ISC_MAGIC_VALID(c, IPSET_INST_MAGIC)
#define IPSET_MAGIC      ISC_MAGIC('I', 'P', 'S', 'm')
#define VALID_IPSET(c) ISC_MAGIC_VALID(c, IPSET_MAGIC)
#define SITE_MAGIC       ISC_MAGIC('I', 'P', 'S', 's')
#define VALID_SITE(c) ISC_MAGIC_VALID(c, SITE_MAGIC)

/**
 * Check an operation for failure.  Assumes that the function
 * using it has a 'result' variable and a 'cleanup' label.
 */
#define CHECK(op)			       \
	do {				       \
		result = (op);		       \
		if (result != ISC_R_SUCCESS) { \
			goto cleanup;	       \
		}			       \
	} while (0)

#define ASSERT(op)				\
	do {					\
		if (!(op)) {			\
			result = ISC_R_FAILURE;	\
			goto cleanup;		\
		}				\
	} while (0)

#define IPSET_NO_TTL 0
#define IPSET_DFT_IPV6 false


/**
 *
 * instance objects read from config
 *
 */

typedef struct ipset ipset_t;
typedef struct ipset {
	unsigned int	       magic;
	isc_mem_t *	       mctx;
	isc_buffer_t*	       name;
#if HAVE_LIBNFTNL
	isc_buffer_t*	       nftable;
	int		       family;
#endif /* if HAVE_LIBNFTNL */
	int		       ttl;
	dns_rdatatype_t	       type;
	ISC_LINK(ipset_t) link;
} ipset_t;
typedef ISC_LIST(ipset_t) ipset_list_t;

typedef struct site site_t;
typedef struct site {
	unsigned int	    magic;
	isc_mem_t *	    mctx;
	dns_name_t	    wildcard;
	ipset_t*	    ipset;
	ISC_LINK(site_t) link;
} site_t;
typedef ISC_LIST(site_t) site_list_t;

typedef struct update_ipset_instance {
	unsigned int		    magic;
	isc_mem_t *		    mctx;
	isc_log_t *		    lctx;

	ns_plugin_t *		    module;
	isc_mutex_t		    hlock;
#if HAVE_LIBIPSET
	bool			    libipset_enabled;
	struct ipset_session*	    seslipset;
#endif /* if HAVE_LIBIPSET */
#if HAVE_LIBNFTNL
	bool			    nftnl_enabled;
#endif /* if HAVE_LIBNFTNL */
	ipset_list_t		    sets;
	site_list_t		    sites;
} update_ipset_instance_t;


#if HAVE_LIBNFTNL
typedef struct {
	isc_log_t *		 lctx;
	struct mnl_socket *	 mnlsocket;
	struct nftnl_set *	 set;
	isc_buffer_t *		 buffer;
	isc_buffer_t *		 resultAsString;
	const char*		 ipsetName;
	const char*		 tableName;
	const char*		 requestName;
	const char*		 client;
	int			 family;
	int			 family_elem;
	bool			 is_timeout;
	uint64_t		 timeout;
	uint64_t		 expiration;
	bool			 present;
} ElemStatus;
#endif /* if HAVE_LIBNFTNL */


/**
 *
 * Config structure
 *
 */
static cfg_type_t cfg_type_sitelist = { "sitelist",
					cfg_parse_bracketed_list,
					cfg_print_bracketed_list,
					cfg_doc_bracketed_list,
					&cfg_rep_list,
					&cfg_type_astring };

static cfg_clausedef_t ipset_clauses[] = {
	{ "sites", &cfg_type_sitelist, 0 },
	{ "ttl", &cfg_type_duration, 0 },
#if HAVE_LIBNFTNL
	{ "nftable", &cfg_type_ustring, 0 },
	{ "family", &cfg_type_ustring, 0 },
#endif /* if HAVE_LIBNFTNL */
	{ "ipv6", &cfg_type_void, 0 },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *ipset_clausesets[] = { ipset_clauses, NULL };

static cfg_type_t cfg_type_ipset = { "ipset",     cfg_parse_named_map,
				     cfg_print_map, cfg_doc_map,
				     &cfg_rep_map,  ipset_clausesets };

static cfg_clausedef_t param_set[] = {
	{ "ipset", &cfg_type_ipset, CFG_CLAUSEFLAG_MULTI }
};

static cfg_clausedef_t *param_sets[] = { param_set, NULL };

static cfg_type_t cfg_type_parameters = {
	"update-ipset-params",
	cfg_parse_mapbody,
	cfg_print_mapbody,
	cfg_doc_mapbody,
	&cfg_rep_map,
	param_sets
};


static isc_result_t ipset_result_string(update_ipset_instance_t*inst, dns_name_t*request, dns_rdata_t*response, isc_buffer_t**pdispdata) {
	REQUIRE(pdispdata != NULL);
	REQUIRE(*pdispdata == NULL);

	isc_result_t result;
	isc_buffer_t*dispdata = NULL;
	int bufsize = response->length * 4;

	do {
		if (dispdata != NULL) {
			bufsize = bufsize * 2;
			isc_buffer_free(&dispdata);
		}
		isc_buffer_allocate(inst->mctx, &dispdata, bufsize);
		result = dns_rdata_totext(response, request, dispdata);
	} while (result == ISC_R_NOSPACE);
	
	if (result == ISC_R_SUCCESS)
		*pdispdata = dispdata;
	return result;
}

#if HAVE_LIBIPSET
/**
 *
 * ipset updates using libipset
 *
 */
static int
ipset_logger_fn(struct ipset_session *session,
		void*logger,
		const char *fmt,
		...) {
	UNUSED(session);

	isc_log_t*lctx = (isc_log_t*)logger;
	va_list args;
	va_start(args, fmt);
	isc_log_write(lctx,
		      NS_LOGCATEGORY_QUERIES,
		      NS_LOGMODULE_HOOKS,
		      ISC_LOG_INFO,
		      fmt,
		      args);
	va_end(args);
	return(0);
}

static void
ipset_add_entry_log_err(update_ipset_instance_t*inst,
			const char*ipsetName,
			int level) {
	const char*msg = ipset_session_report_msg(inst->seslipset);
	if (msg == NULL || strlen(msg) > 1000) {
		isc_log_write(inst->lctx,
			      NS_LOGCATEGORY_QUERIES,
			      NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "update-ipset: set=%s ipset library return wrong message",
			      ipsetName);
		return;
	}
	isc_log_write(inst->lctx,
		      NS_LOGCATEGORY_QUERIES,
		      NS_LOGMODULE_HOOKS,
		      level,
		      "update-ipset: set=%s: %.*s",
		      ipsetName,
		      (int)strlen(msg) - 1,
		      msg);
}

static const char*
labelIpsetFamily(int family) {
	return
		((family == NFPROTO_IPV4)?"inet":
		 ((family == NFPROTO_IPV6)?"inet6":"invalid"));
}

static isc_result_t
ipset_add_entry(update_ipset_instance_t*inst,
		const char*ipsetName,
		dns_rdata_t*address,
		int ttl) {
	isc_result_t result = ISC_R_SUCCESS;
	int r;

	uint8_t family = 0;
	if (address->type == dns_rdatatype_a) {
		family = NFPROTO_IPV4;
	}
	if (address->type == dns_rdatatype_aaaa) {
		family = NFPROTO_IPV6;
	}
	ASSERT(family != 0);

	LOCK(&inst->hlock);

	if (ttl != 0) {
		r = ipset_session_data_set(inst->seslipset,
					   IPSET_OPT_TIMEOUT,
					   &ttl);
		ASSERT(r == 0);
	}

	r = ipset_session_data_set(inst->seslipset, IPSET_SETNAME, ipsetName);
	ASSERT(r == 0);

	const struct ipset_type *type = ipset_type_get(inst->seslipset,
						       IPSET_CMD_ADD);
	if (type == NULL) {
		ipset_add_entry_log_err(inst, ipsetName, ISC_LOG_WARNING);
		goto cleanup;
	}

	const int*psetFamily = ipset_session_data_get(inst->seslipset,
						      IPSET_OPT_FAMILY);
	ASSERT(psetFamily != NULL);

	if (*psetFamily != family) {
		isc_log_write(inst->lctx,
			      NS_LOGCATEGORY_QUERIES,
			      NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "update-ipset: set=%s - incompatible address family (set family is %s, not %s)",
			      ipsetName,
			      labelIpsetFamily(*psetFamily),
			      labelIpsetFamily(family));
		goto cleanup;
	}

	r =
		ipset_session_data_set(inst->seslipset,
				       IPSET_OPT_IP,
				       address->data);
	if (r != 0) {
		ipset_add_entry_log_err(inst, ipsetName, ISC_LOG_ERROR);
		goto cleanup;
	}
	r = ipset_cmd(inst->seslipset, IPSET_CMD_ADD, /*lineno*/ 0);
	if (r != 0) {
		ipset_add_entry_log_err(inst, ipsetName, ISC_LOG_ERROR);
		goto cleanup;
	}

	isc_log_write(inst->lctx,
		      NS_LOGCATEGORY_QUERIES,
		      NS_LOGMODULE_HOOKS,
		      ISC_LOG_INFO,
		      "update-ipset: set=%s: new entry added/updated",
		      ipsetName);

 cleanup:

	ipset_session_report_reset(inst->seslipset);
	UNLOCK(&inst->hlock);
	return(result);
}

static isc_result_t
init_libipset(update_ipset_instance_t *inst, isc_log_t *lctx) {
	isc_result_t result  = ISC_R_SUCCESS;
	ipset_load_types();
	inst->seslipset = ipset_session_init(&ipset_logger_fn, lctx);
	ASSERT(inst->seslipset != NULL);
	ipset_envopt_set(inst->seslipset, IPSET_ENV_EXIST);
 cleanup:
	return(result);
}
#endif /* if HAVE_LIBIPSET */

#if HAVE_LIBNFTNL


static isc_result_t
init_libnftnl(struct mnl_socket **pnftnl) {
	isc_result_t result  = ISC_R_SUCCESS;

	*pnftnl = mnl_socket_open(NETLINK_NETFILTER);
	ASSERT(*pnftnl != NULL);
	ASSERT(mnl_socket_bind(*pnftnl, 0, MNL_SOCKET_AUTOPID) >= 0);
	int opt = 1;
	mnl_socket_setsockopt(*pnftnl, NETLINK_NO_ENOBUFS, &opt, sizeof(opt));

	return(result);
 cleanup:
	if (*pnftnl != NULL) {
		mnl_socket_close(*pnftnl);
	}

	return(result);
}

static void
exit_libnftnl(struct mnl_socket **pnftnl) {
	if (*pnftnl != NULL) {
		mnl_socket_close(*pnftnl);
	}
	*pnftnl = NULL;
}

static int
nft_cb_get_set(const struct nlmsghdr *nlh, void *data)
{
	ElemStatus*pStatus = (ElemStatus*)data;
	if (nftnl_set_nlmsg_parse(nlh, pStatus->set) < 0) {
		return(MNL_CB_ERROR);
	}

	if (nftnl_set_is_set(pStatus->set, NFTNL_SET_TIMEOUT)) {
		pStatus->timeout = nftnl_set_get_u64(pStatus->set,
						     NFTNL_SET_TIMEOUT);
	}
	if (nftnl_set_is_set(pStatus->set, NFTNL_SET_FLAGS)) {
		uint32_t flags = nftnl_set_get_u32(pStatus->set,
						   NFTNL_SET_FLAGS);
		pStatus->is_timeout = (flags & NFT_SET_TIMEOUT) ==
				      NFT_SET_TIMEOUT;
	}

	return(MNL_CB_OK);
}

static int
setel_cb(struct nftnl_set_elem *nlse, void *data)
{
	ElemStatus*pStatus = (ElemStatus*)data;
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_EXPIRATION)) {
		pStatus->expiration = nftnl_set_elem_get_u64(nlse,
							     NFTNL_SET_ELEM_EXPIRATION);
	}
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_TIMEOUT)) {
		pStatus->timeout = nftnl_set_elem_get_u64(nlse,
							  NFTNL_SET_ELEM_TIMEOUT);
	}
	pStatus->present = true;
	return(MNL_CB_OK);
}

static int
nft_cb_get_set_elem(const struct nlmsghdr *nlh, void *data)
{
	ElemStatus*pStatus = (ElemStatus*)data;

	if (nftnl_set_elems_nlmsg_parse(nlh, pStatus->set) < 0) {
		return(MNL_CB_ERROR);
	}

	if (nftnl_set_is_set(pStatus->set, NFTNL_SET_TIMEOUT)) {
		pStatus->timeout = nftnl_set_get_u64(pStatus->set,
						     NFTNL_SET_TIMEOUT);
	}
	nftnl_set_elem_foreach(pStatus->set, setel_cb, data);
	return(MNL_CB_OK);
}

static isc_result_t
nftnl_elem_status(struct nftnl_set *s,
		  ElemStatus*pStatus,
		  uint16_t type,
		  mnl_cb_t callback,
		  bool mustExist) {
	isc_result_t result  = ISC_R_SUCCESS;
	struct nlmsghdr *nlh = nftnl_set_nlmsg_build_hdr(pStatus->buffer->base,
							 type,
							 pStatus->family,
							 NLM_F_ACK,
							 0);
	nftnl_set_elems_nlmsg_build_payload(nlh, s);
	if (mnl_socket_sendto(pStatus->mnlsocket, nlh, nlh->nlmsg_len) < 0) {
		isc_log_write(pStatus->lctx,
			      NS_LOGCATEGORY_QUERIES,
			      NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "update-ipset: req=%s resp=%.*s client=%s set=%s table=%s family=%d addrfamily=%d: error checking %s: %s",
			      pStatus->requestName,
			      pStatus->resultAsString->used, (const char*)pStatus->resultAsString->base,
			      pStatus->client,
			      pStatus->ipsetName,
			      pStatus->tableName,
			      pStatus->family,
			      pStatus->family_elem,
			      type == NFT_MSG_GETSET ? "set":"element",
			      strerror(errno));
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	int32_t portid = mnl_socket_get_portid(pStatus->mnlsocket);

	int ret = mnl_socket_recvfrom(pStatus->mnlsocket,
				      pStatus->buffer->base,
				      pStatus->buffer->length);
	while (ret > 0) {
		ret = mnl_cb_run(pStatus->buffer->base,
				 ret,
				 0,
				 portid,
				 callback,
				 pStatus);
		if (ret <= 0) {
			break;
		}
		ret = mnl_socket_recvfrom(pStatus->mnlsocket,
					  pStatus->buffer->base,
					  pStatus->buffer->length);
	}
	if (ret == -1) {
		if (!mustExist && errno == ENOENT) {
			goto cleanup;
		}

		isc_log_write(pStatus->lctx,
			      NS_LOGCATEGORY_QUERIES,
			      NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "update-ipset: req=%s resp=%.*s client=%s set=%s table=%s family=%d addrfamily=%d: error checking %s: %s",
			      pStatus->requestName,
			      pStatus->resultAsString->used, (const char*)pStatus->resultAsString->base,
			      pStatus->client,
			      pStatus->ipsetName,
			      pStatus->tableName,
			      pStatus->family,
			      pStatus->family_elem,
			      type == NFT_MSG_GETSET ? "set":"element",
			      errno == ENOENT?"absent":strerror(errno));
		result = ISC_R_FAILURE;
		goto cleanup;
	}
 cleanup:
	return(result);
}

static isc_result_t
nft_set_add_entry(update_ipset_instance_t*inst,
		  const char*tableName,
		  const char*ipsetName,
		  const char*requestName,
		  const char*client,
		  dns_name_t*name_ans,
		  dns_rdata_t*address,
		  unsigned int ttl,
		  dns_ttl_t entry_ttl,
		  int family) {
	ElemStatus sts;
	isc_result_t result  = ISC_R_SUCCESS;
	struct nftnl_set *s = NULL;
	struct nftnl_set_elem *e = NULL;
	struct nlmsghdr *nlh = NULL;

	if (address->type == dns_rdatatype_a) {
		sts.family_elem = NFPROTO_IPV4;
	}
	if (address->type == dns_rdatatype_aaaa) {
		sts.family_elem = NFPROTO_IPV6;
	}
	ASSERT(sts.family_elem != 0);
	if (family == 0) {
		family = sts.family_elem;
	}

	sts.family = family;
	sts.lctx = inst->lctx;
	sts.mnlsocket = NULL;
	sts.buffer = NULL;
	sts.resultAsString = NULL;
	sts.tableName = tableName;
	sts.ipsetName = ipsetName;
	sts.requestName = requestName;
	sts.client = client;
	sts.present = false;
	sts.timeout = 0;
	sts.expiration = 0;
	sts.is_timeout = false;
	sts.set = nftnl_set_alloc();
	if (sts.set == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	s = nftnl_set_alloc();
	if (s == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}
	e = nftnl_set_elem_alloc();
	if (e == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}
	result = ipset_result_string(inst, name_ans, address, &sts.resultAsString);

	isc_buffer_allocate(inst->mctx, &sts.buffer, MNL_SOCKET_BUFFER_SIZE);

	nftnl_set_set_str(s, NFTNL_SET_TABLE, sts.tableName);
	nftnl_set_set_str(s, NFTNL_SET_NAME, sts.ipsetName);
	nftnl_set_set_u32(s, NFTNL_SET_FAMILY, sts.family_elem);

	CHECK(init_libnftnl(&sts.mnlsocket ));

	/* Set must exist */
	CHECK(nftnl_elem_status(s, &sts, NFT_MSG_GETSET, nft_cb_get_set,
				true));

	nftnl_set_elem_set(e,
			   NFTNL_SET_ELEM_KEY,
			   address->data,
			   address->length);
	nftnl_set_elem_add(s, e);
	/* Element may not exist */
	CHECK(nftnl_elem_status(s, &sts, NFT_MSG_GETSETELEM,
				nft_cb_get_set_elem, false));

	/* Batch setup */
	struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(
		sts.buffer->base,
		sts.buffer->length);

	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), 0);
	mnl_nlmsg_batch_next(batch);

	if (sts.is_timeout) {
		/* if timeout flag but not default value on set => use entry TTL */
		if (ttl == 0 && sts.timeout == 0) {
			ttl = entry_ttl;
		}
		if (ttl != 0) {
			nftnl_set_elem_set_u64(e,
					       NFTNL_SET_ELEM_TIMEOUT,
					       ttl * 1000);
		}
	} else {
		ttl = 0;
	}

	if (sts.present) {
		bool isTTLChanged =
			(ttl != 0 && sts.is_timeout &&
			 ttl * 1000 != sts.timeout);
		bool isExpirationLongEnough = sts.timeout == 0 ||
					      sts.expiration == 0 ||
					      (sts.expiration * 100.0 /
					       sts.timeout) > 50.0;
		if (!isTTLChanged && isExpirationLongEnough) {
			/* timeout long enough => all good */
			isc_log_write(inst->lctx,
				      NS_LOGCATEGORY_QUERIES,
				      NS_LOGMODULE_HOOKS,
				      ISC_LOG_INFO,
				      "update-ipset: req=%s resp=%.*s client=%s set=%s table=%s family=%d addrfamily=%d: nftnl element already present (expire: %ld/%ld)",
				      sts.requestName,
				      sts.resultAsString->used, (const char*)sts.resultAsString->base,
				      sts.client,
				      sts.ipsetName,
				      sts.tableName,
				      sts.family,
				      sts.family_elem,
				      sts.expiration,
				      sts.timeout);
			goto cleanup;
		}

		/* must recreate! */
		nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					    NFT_MSG_DELSETELEM, sts.family,
					    NLM_F_ACK,
					    0);
		nftnl_set_elems_nlmsg_build_payload(nlh, s);
		mnl_nlmsg_batch_next(batch);
	}

	nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				    NFT_MSG_NEWSETELEM, sts.family,
				    NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
				    0);
	nftnl_set_elems_nlmsg_build_payload(nlh, s);
	mnl_nlmsg_batch_next(batch);

	nftnl_batch_end(mnl_nlmsg_batch_current(batch), 0);
	mnl_nlmsg_batch_next(batch);




	int32_t portid = mnl_socket_get_portid(sts.mnlsocket);
	if (mnl_socket_sendto(sts.mnlsocket, mnl_nlmsg_batch_head(batch),
			      mnl_nlmsg_batch_size(batch)) < 0) {
		isc_log_write(inst->lctx,
			      NS_LOGCATEGORY_QUERIES,
			      NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "update-ipset: req=%s resp=%.*s client=%s set=%s table=%s family=%d addrfamily=%d: error sending nftnl ipset changes: %s",
			      sts.requestName,
			      sts.resultAsString->used, (const char*)sts.resultAsString->base,
			      sts.client,
			      sts.ipsetName,
			      sts.tableName,
			      sts.family,
			      sts.family_elem,
			      strerror(errno));
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	mnl_nlmsg_batch_stop(batch);

	int ret = mnl_socket_recvfrom(sts.mnlsocket,
				      sts.buffer->base,
				      sts.buffer->length);
	while (ret > 0) {
		ret = mnl_cb_run(sts.buffer->base,
				 ret,
				 0,
				 portid,
				 NULL,
				 NULL);
		if (ret <= 0) {
			break;
		}
		ret = mnl_socket_recvfrom(sts.mnlsocket,
					  sts.buffer->base,
					  sts.buffer->length);
	}
	if (ret == -1) {
		isc_log_write(inst->lctx,
			      NS_LOGCATEGORY_QUERIES,
			      NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "update-ipset: req=%s resp=%.*s client=%s set=%s table=%s family=%d addrfamily=%d: error setting nftnl ipset element: %s",
			      sts.requestName,
			      sts.resultAsString->used, (const char*)sts.resultAsString->base,
			      sts.client,
			      sts.ipsetName,
			      sts.tableName,
			      sts.family,
			      sts.family_elem,
			      strerror(errno));
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	isc_log_write(inst->lctx,
		      NS_LOGCATEGORY_QUERIES,
		      NS_LOGMODULE_HOOKS,
		      ISC_LOG_INFO,
		      "update-ipset: req=%s resp=%.*s client=%s set=%s table=%s family=%d addrfamily=%d: nftnl ipset element added/updated, ttl=%d",
		      sts.requestName,
		      sts.resultAsString->used, (const char*)sts.resultAsString->base,
		      sts.client,
		      sts.ipsetName,
		      sts.tableName,
		      sts.family,
		      sts.family_elem, ttl);

 cleanup:
	exit_libnftnl(&sts.mnlsocket);


	if (sts.resultAsString != NULL) {
		isc_buffer_free(&sts.resultAsString);
	}
	if (sts.buffer != NULL) {
		isc_buffer_free(&sts.buffer);
	}
	if (s != NULL) {
		nftnl_set_free(s);
	}
	return(result);
}


static isc_result_t
getfamilyfromobj( const cfg_obj_t*family, int*pfamily) {
	isc_result_t result = ISC_R_SUCCESS;
	REQUIRE(family != NULL);
	REQUIRE(pfamily != NULL);

	ASSERT(cfg_obj_isstring(family));
	const char*cstr = cfg_obj_asstring(family);
	if (strcmp(cstr, "ip") == 0) {
		*pfamily = NFPROTO_IPV4;
	} else if (strcmp(cstr, "ip6") == 0) {
		*pfamily = NFPROTO_IPV6;
	} else if (strcmp(cstr, "inet") == 0) {
		*pfamily = NFPROTO_INET;
	} else if (strcmp(cstr, "arp") == 0) {
		*pfamily = NFPROTO_ARP;
	} else if (strcmp(cstr, "bridge") == 0) {
		*pfamily = NFPROTO_BRIDGE;
	} else if (strcmp(cstr, "netdev") == 0) {
		*pfamily = NFPROTO_NETDEV;
	} else {
		result = ISC_R_FAMILYNOSUPPORT;
	}

 cleanup:
	return(result);
}
#endif /* if HAVE_LIBNFTNL */

static
bool
dns_name_matches (const dns_name_t *name, const dns_name_t *wname) {
	if (dns_name_iswildcard(wname)) {
		return(dns_name_matcheswildcard(name, wname));
	}

	return(dns_name_equal(name, wname));
}

/**
 *
 * Response filter: do we need to update an ipset entry?
 *
 */
static bool
ipset_handle_name_response(update_ipset_instance_t*inst,
			   dns_name_t*request,
			   dns_ttl_t ttl,
			   const char*requestName,
			   const char*client,
			   dns_name_t*name_ans,
			   dns_rdata_t*response)
{
	bool match = false;
	if (response->rdclass != dns_rdataclass_in) {
		return match;
	}
	if (response->type != dns_rdatatype_a &&
	    response->type != dns_rdatatype_aaaa) {
		return match;
	}

	site_t*site = ISC_LIST_HEAD(inst->sites);
	while (site != NULL) {
		if (site->ipset->type == response->type &&
		    dns_name_matches(request, &site->wildcard)) {
			ipset_t*ipset = site->ipset;
			match = true;
			const char*n = isc_buffer_base(ipset->name);
#if HAVE_LIBNFTNL
			if (ipset->nftable != NULL) {
				const char*t = isc_buffer_base(ipset->nftable);
				nft_set_add_entry(inst,
						  t,
						  n,
						  requestName,
						  client,
						  name_ans,
						  response,
						  site->ipset->ttl, ttl,
						  site->ipset->family);
			}
#if HAVE_LIBIPSET
			else
#endif /* if HAVE_LIBIPSET */
#endif /* if HAVE_LIBNFTNL */
#if HAVE_LIBIPSET
			{
				ipset_add_entry(inst,
						n,
						response,
						site->ipset->ttl);
			}
#endif /* if HAVE_LIBIPSET */
		}

		site = ISC_LIST_NEXT(site, link);
	}
	return match;
}


static void
ipset_log_request_result_info(update_ipset_instance_t*inst,
			      const char*requestname,
			      const char*client,
			      dns_name_t*request,
			      dns_rdata_t*response) {
	isc_result_t result;
	isc_buffer_t*dispdata = NULL;

	result = ipset_result_string(inst, request, response, &dispdata);

	if (result != ISC_R_SUCCESS)
		return;

	isc_log_write(inst->lctx,
		      NS_LOGCATEGORY_QUERIES,
		      NS_LOGMODULE_HOOKS,
		      ISC_LOG_INFO,
		      "update-ipset: req=%s resp=%.*s client=%s CLS=%d TYPE=%d",
		      requestname, 
		      dispdata->used, (const char*) dispdata->base,
		      client,
		      response->rdclass,
		      response->type		      
		      );
	isc_buffer_free(&dispdata);
}

static ns_hookresult_t
filter_query_done_send(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *)arg;
	update_ipset_instance_t *inst = (update_ipset_instance_t *)cbdata;

	dns_message_t *msg = qctx->client->message;
	dns_name_t *name_ans, *next_name_ans;
	dns_rdataset_t *rdataset, *next_rdataset;
	isc_netaddr_t netaddr;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_result_t result;

	if (ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ANSWER])) {
		return (NS_HOOK_CONTINUE);
	}

	name_ans = ISC_LIST_HEAD(msg->sections[DNS_SECTION_ANSWER]);

	char requestname[DNS_NAME_FORMATSIZE];
	char client[ISC_NETADDR_FORMATSIZE];

	dns_name_format(qctx->client->query.origqname, requestname,
			sizeof(requestname));
	isc_netaddr_fromsockaddr(&netaddr, &qctx->client->peeraddr);
	isc_netaddr_format(&netaddr, client, sizeof(client));

	while (name_ans != NULL) {
		next_name_ans = ISC_LIST_NEXT(name_ans, link);
		rdataset = ISC_LIST_HEAD(name_ans->list);
		while (rdataset != NULL) {
			next_rdataset = ISC_LIST_NEXT(rdataset, link);
			result = dns_rdataset_first(rdataset);
			do {
				dns_rdata_init(&rdata);
				dns_rdataset_current(rdataset, &rdata);
				if (rdata.rdclass == dns_rdataclass_in &&
				    ( rdata.type == dns_rdatatype_a ||
				      rdata.type == dns_rdatatype_aaaa)) {
					if (!ipset_handle_name_response(inst,
								   qctx->client->query.origqname,
								   rdataset->ttl,
								   requestname,
								   client,
								   name_ans,
								   &rdata))
						ipset_log_request_result_info(inst,
								      requestname,
								      client,
								      name_ans,
								      &rdata);
				}
				result = dns_rdataset_next(rdataset);
			} while(result == ISC_R_SUCCESS);
			rdataset = next_rdataset;
		}
		name_ans = next_name_ans;
	}
	*resp = ISC_R_SUCCESS;
	return (NS_HOOK_CONTINUE);
}


static void
install_hooks(ns_hooktable_t *hooktable,
	      isc_mem_t *mctx,
	      update_ipset_instance_t *inst) {
	const ns_hook_t filter_donesend = {
		.action = filter_query_done_send,
		.action_data = inst,
	};
	ns_hook_add(hooktable, mctx, NS_QUERY_DONE_SEND, &filter_donesend);
}


/*
 * Returns plugin API version for compatibility checks.
 */
int
plugin_version(void) {
	return (NS_PLUGIN_VERSION);
}

/**
 *
 * Configuration init
 *
 */

static isc_result_t
site_create(isc_mem_t *mctx,
	    ipset_t*ipset,
	    site_t**sitep,
	    const cfg_obj_t*siteobj) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_buffer_t* fixed_name = NULL;
	site_t *site;
	REQUIRE(mctx != NULL);
	REQUIRE(sitep != NULL && *sitep == NULL);
	REQUIRE(cfg_obj_isstring(siteobj));

	site = isc_mem_get(mctx, sizeof(site_t));
	dns_name_init(&site->wildcard, NULL);
	site->mctx = NULL;

	isc_mem_attach(mctx, &site->mctx);
	ISC_LINK_INIT(site, link);

	const char*siteval = cfg_obj_asstring(siteobj);
	isc_buffer_allocate(site->mctx,
			    &fixed_name,
			    strlen(siteval) + 2);
	strcpy(fixed_name->base, siteval);
	if (((char*)fixed_name->base)[strlen(fixed_name->base)-1] != '.')
		strcat(fixed_name->base, ".");
	isc_buffer_allocate(site->mctx,
			    &site->wildcard.buffer,
			    strlen(fixed_name->base) + 1);
	CHECK(dns_name_fromstring2(&site->wildcard, fixed_name->base, NULL, 0,
				   site->mctx));
	
	REQUIRE(
		(site->wildcard.attributes & DNS_NAMEATTR_ABSOLUTE) ==
		DNS_NAMEATTR_ABSOLUTE);

	site->ipset = ipset;
	site->magic = SITE_MAGIC;
	*sitep = site;

	return(result);

 cleanup:
	if (fixed_name != NULL) {
		isc_buffer_free(&fixed_name);
	}
	if (site->wildcard.buffer != NULL) {
		isc_buffer_free(&site->wildcard.buffer);
	}
	return(result);
}

static void
site_free(site_t*site) {
	site->magic = 0;
	site->ipset = NULL;
	isc_buffer_free(&site->wildcard.buffer);
	dns_name_invalidate(&site->wildcard);
	isc_mem_putanddetach(&site->mctx, site, sizeof(*site));
}

static
isc_result_t
ipset_create(isc_mem_t *mctx,
	     isc_log_t *lctx,
	     ipset_t**ipsetp,
	     const cfg_obj_t*setobj) {
#if HAVE_LIBIPSET
	UNUSED(lctx);
#endif
	isc_result_t result = ISC_R_SUCCESS;
	ipset_t*ipset = NULL;
	const char*setname;
	const cfg_obj_t*ttl = NULL;
	const cfg_obj_t*family = NULL;
	const cfg_obj_t*setv6 = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(ipsetp != NULL && *ipsetp == NULL);
	REQUIRE(cfg_obj_ismap(setobj));

	ipset = isc_mem_get(mctx, sizeof(ipset_t));
	ipset->mctx = NULL;
	isc_mem_attach(mctx, &ipset->mctx);
	ISC_LINK_INIT(ipset, link);

	const cfg_obj_t*name = cfg_map_getname(setobj);
	REQUIRE(cfg_obj_isstring(name));
	setname = cfg_obj_asstring(name);

	ipset->name = NULL;
	isc_buffer_allocate(mctx, &ipset->name, strlen(setname) + 1);
	isc_buffer_putstr(ipset->name, setname);
	isc_buffer_putuint8(ipset->name, 0);


	if (cfg_map_get(setobj, "ttl", &ttl) == ISC_R_SUCCESS) {
		ASSERT(ttl != NULL && cfg_obj_isduration(ttl));
		ipset->ttl = cfg_obj_asduration(ttl);
	} else {
		ipset->ttl = IPSET_NO_TTL;
	}

	bool setelemv6 = false;
	ipset->type = dns_rdatatype_a;
	if (cfg_map_get(setobj, "ipv6", &setv6) == ISC_R_SUCCESS) {
		setelemv6 = true;
		ipset->type = dns_rdatatype_aaaa;
	}
#if HAVE_LIBNFTNL
	ipset->family = NFPROTO_IPV4;
	if (cfg_map_get(setobj, "family", &family) == ISC_R_SUCCESS) {
		CHECK(getfamilyfromobj(family, &ipset->family));
		if (!setelemv6 && ipset->family == NFPROTO_IPV6) {
			ipset->type = dns_rdatatype_aaaa;
		}
	} else {
		if (setelemv6 && ipset->type == dns_rdatatype_aaaa) {
			ipset->family = NFPROTO_IPV6;
		}
		if (setelemv6 && ipset->type == dns_rdatatype_a) {
			ipset->family = NFPROTO_IPV4;
		}
	}
	const cfg_obj_t*nftable = NULL;
	ipset->nftable = NULL;
	result = cfg_map_get(setobj, "nftable", &nftable);
	if (result == ISC_R_SUCCESS) {
		ASSERT(cfg_obj_isstring(nftable));
		const char*nftablestr = cfg_obj_asstring(nftable);
		isc_buffer_allocate(mctx,
				    &ipset->nftable,
				    strlen(nftablestr) + 1);
		isc_buffer_putstr(ipset->nftable, nftablestr);
		isc_buffer_putuint8(ipset->nftable, 0);
	} else {
#if HAVE_LIBIPSET
		result = ISC_R_SUCCESS;
#else  /* if HAVE_LIBIPSET */
		isc_log_write(lctx,
			      NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "update-ipset: nftable option missing for set '%s'",
			      setname);
		goto    cleanup;        /* no libipset, nftable must exist */
#endif /* if HAVE_LIBIPSET */
	}
#endif /* if HAVE_LIBNFTNL */
	ipset->magic = IPSET_MAGIC;
	*ipsetp = ipset;

	return(result);
 cleanup:
	if (ipset != NULL) {
		if (ipset->name != NULL) {
			isc_buffer_free(&ipset->name);
		}
		ipset->name = NULL;
		if (ipset->nftable != NULL) {
			isc_buffer_free(&ipset->nftable);
		}
		ipset->nftable = NULL;
		isc_mem_putanddetach(&ipset->mctx, ipset, sizeof(*ipset));
	}

	return(result);
}

static void
ipset_free(ipset_t*set) {
	set->magic = 0;
	isc_buffer_free(&set->name);
#if HAVE_LIBNFTNL
	if (set->nftable != NULL) {
		isc_buffer_free(&set->nftable);
	}
#endif /* if HAVE_LIBNFTNL */
	isc_mem_putanddetach(&set->mctx, set, sizeof(*set));
}

static isc_result_t
parse_parameters(update_ipset_instance_t *inst,
		 const char *parameters,
		 const char *cfg_file,
		 unsigned long cfg_line,
		 isc_mem_t *mctx,
		 isc_log_t *lctx) {
	isc_result_t result = ISC_R_SUCCESS;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *param_obj = NULL;
	const cfg_obj_t *obj = NULL;
	isc_buffer_t b;

	CHECK(cfg_parser_create(mctx, lctx, &parser));

	isc_buffer_constinit(&b, parameters, strlen(parameters));
	isc_buffer_add(&b, strlen(parameters));
	CHECK(cfg_parse_buffer(parser, &b, cfg_file, cfg_line,
			       &cfg_type_parameters, 0, &param_obj));

	ISC_LIST_INIT(inst->sets);
	ISC_LIST_INIT(inst->sites);
#if HAVE_LIBIPSET
	inst->libipset_enabled = false;
#endif /* if HAVE_LIBIPSET */
#if HAVE_LIBNFTNL
	inst->nftnl_enabled = false;
#endif /* if HAVE_LIBNFTNL */

	CHECK(cfg_map_get(param_obj, "ipset", &obj));
	if (result == ISC_R_NOTFOUND) {
		result = ISC_R_SUCCESS;
		goto cleanup;
	}
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	ASSERT(cfg_obj_islist(obj));
	for (const cfg_listelt_t*element = cfg_list_first(obj);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		const cfg_obj_t*setobj = cfg_listelt_value(element);
		const cfg_obj_t*sites = NULL;
		ipset_t *ipset = NULL;

		CHECK(ipset_create(mctx, lctx, &ipset, setobj));

#if HAVE_LIBNFTNL
		if (ipset->nftable != NULL) {
			inst->nftnl_enabled = true;
		}
  #if HAVE_LIBIPSET
		else {
			inst->libipset_enabled = true;
		}
  #endif /* if HAVE_LIBIPSET */
#elif HAVE_LIBIPSET
		inst->libipset_enabled = true;
#endif /* if HAVE_LIBNFTNL */
		ISC_LIST_APPEND(inst->sets, ipset, link);

		CHECK(cfg_map_get(setobj, "sites", &sites));
		ASSERT(cfg_obj_islist(sites));
		for (const cfg_listelt_t*site_elem = cfg_list_first(sites);
		     site_elem != NULL;
		     site_elem = cfg_list_next(site_elem))
		{
			const cfg_obj_t*site_obj =
				cfg_listelt_value(site_elem);
			site_t*site = NULL;
			CHECK(site_create(mctx, ipset, &site, site_obj));
			ISC_LIST_APPEND(inst->sites, site, link);
		}
	}

 cleanup:
	if (param_obj != NULL) {
		cfg_obj_destroy(parser, &param_obj);
	}
	if (parser != NULL) {
		cfg_parser_destroy(&parser);
	}
	return(result);
}

static isc_result_t
check_parameters(const char *parameters,
		 const char *cfg_file,
		 unsigned long cfg_line,
		 isc_mem_t *mctx,
		 isc_log_t *lctx) {
	isc_result_t result = ISC_R_SUCCESS;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *param_obj = NULL;
	const cfg_obj_t *obj = NULL;
	isc_buffer_t b;

	CHECK(cfg_parser_create(mctx, lctx, &parser));

	isc_buffer_constinit(&b, parameters, strlen(parameters));
	isc_buffer_add(&b, strlen(parameters));
	CHECK(cfg_parse_buffer(parser, &b, cfg_file, cfg_line,
			       &cfg_type_parameters, 0, &param_obj));

	result = cfg_map_get(param_obj, "ipset", &obj);
	if (result == ISC_R_NOTFOUND) {
		result = ISC_R_SUCCESS;
		goto cleanup;
	}
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	ASSERT(cfg_obj_islist(obj));
	for (const cfg_listelt_t*element = cfg_list_first(obj);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		const cfg_obj_t*setobj = cfg_listelt_value(element);
		const cfg_obj_t*sites = NULL;
		ipset_t *ipset = NULL;

		CHECK(ipset_create(mctx, lctx, &ipset, setobj));

		CHECK(cfg_map_get(setobj, "sites", &sites));
		ASSERT(cfg_obj_islist(sites));
		for (const cfg_listelt_t*site_elem = cfg_list_first(sites);
		     site_elem != NULL;
		     site_elem = cfg_list_next(site_elem))
		{
			const cfg_obj_t*site_obj =
				cfg_listelt_value(site_elem);
			site_t*site = NULL;
			CHECK(site_create(mctx, ipset, &site, site_obj));
			site_free(site);
		}
		ipset_free(ipset);
	}

 cleanup:
	if (param_obj != NULL) {
		cfg_obj_destroy(parser, &param_obj);
	}
	if (parser != NULL) {
		cfg_parser_destroy(&parser);
	}
	return(result);
}

/**
 *
 * Plugin register/destroy
 *
 */

isc_result_t
plugin_register(const char *parameters,
		const void *cfg,
		const char *cfg_file,
		unsigned long cfg_line,
		isc_mem_t *mctx,
		isc_log_t *lctx,
		void *actx,
		ns_hooktable_t *hooktable,
		void **instp) {
	UNUSED(cfg);
	UNUSED(actx);
	UNUSED(parameters);
	update_ipset_instance_t *inst = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	isc_log_write(lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
		      ISC_LOG_INFO,
		      "registering 'update-ipset' "
		      "module from %s:%lu, %s parameters",
		      cfg_file, cfg_line, parameters != NULL ? "with" : "no");

	if (parameters == NULL) {
		return(ISC_R_FAILURE);
	}

	REQUIRE(mctx != NULL);
	REQUIRE(instp != NULL && *instp == NULL);
	inst = isc_mem_get(mctx, sizeof(update_ipset_instance_t));
	inst->mctx = NULL;

	install_hooks(hooktable, mctx, inst);

	inst->lctx = lctx;

	CHECK(parse_parameters(inst, parameters, cfg_file,
			       cfg_line, mctx, lctx));

#if HAVE_LIBIPSET
	if (inst->libipset_enabled) {
		isc_log_write(lctx,
			      NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS,
			      ISC_LOG_INFO,
			      "update-ipset: libipset mode enabled");
		CHECK(init_libipset(inst, lctx));
	}
#endif /* if HAVE_LIBIPSET */
#if HAVE_LIBNFTNL
	if (inst->nftnl_enabled) {
		isc_log_write(lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_INFO,
			      "update-ipset: nftnl mode enabled");
	}
#endif /* if HAVE_LIBNFTNL */

	isc_mutex_init(&inst->hlock);

	inst->magic = IPSET_INST_MAGIC;
	isc_mem_attach(mctx, &inst->mctx);

	*instp = inst;

 cleanup:
	if (result != ISC_R_SUCCESS) {
		plugin_destroy((void **)&inst);
	}
	return (result);
}

isc_result_t
plugin_check(const char *parameters,
	     const void *cfg,
	     const char *cfg_file,
	     unsigned long cfg_line,
	     isc_mem_t *mctx,
	     isc_log_t *lctx,
	     void *actx) {
	isc_result_t result = ISC_R_SUCCESS;
	UNUSED(actx);
	UNUSED(cfg);

	CHECK(check_parameters(parameters, cfg_file,
			       cfg_line, mctx, lctx));
 cleanup:
	return(ISC_R_SUCCESS);
}

void
plugin_destroy(void **instp) {
	if (instp == NULL || *instp == NULL) {
		return;
	}

	update_ipset_instance_t *inst = (update_ipset_instance_t *)*instp;
	if (VALID_IPSET_INST(inst)) {
		inst->magic = 0;
		site_t*site = ISC_LIST_HEAD(inst->sites);
		while (site != NULL) {
			site_t*next = ISC_LIST_NEXT(site, link);
			site_free(site);
			site = next;
		}
		ipset_t*set = ISC_LIST_HEAD(inst->sets);
		while (set != NULL) {
			ipset_t*next = ISC_LIST_NEXT(set, link);
			ipset_free(set);
			set = next;
		}

		isc_mutex_destroy(&inst->hlock);
		isc_mem_putanddetach(&inst->mctx, inst, sizeof(*inst));
	}
	*instp = NULL;
}
