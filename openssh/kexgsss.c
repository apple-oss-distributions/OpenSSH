/*
 * Copyright (c) 2001-2005 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef GSSAPI

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include "xmalloc.h"
#include "buffer.h"
#include "bufaux.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "ssh-gss.h"
#include "monitor_wrap.h"

void
kexgss_server(Kex *kex)
{
	OM_uint32 maj_status, min_status;
	
	/* 
	 * Some GSSAPI implementations use the input value of ret_flags (an
 	 * output variable) as a means of triggering mechanism specific 
 	 * features. Initializing it to zero avoids inadvertently 
 	 * activating this non-standard behaviour.
	 */

	OM_uint32 ret_flags = 0;
	gss_buffer_desc gssbuf, recv_tok, msg_tok;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	Gssctxt *ctxt = NULL;
	unsigned int klen, kout;
	unsigned char *kbuf, *hash;
	DH *dh;
	int min = -1, max = -1, nbits = -1;
	BIGNUM *shared_secret = NULL;
	BIGNUM *dh_client_pub = NULL;
	int type = 0;
	int gex;
	u_int slen;
	gss_OID oid;
	
	/* Initialise GSSAPI */

	/* If we're rekeying, privsep means that some of the private structures
	 * in the GSSAPI code are no longer available. This kludges them back
         * into life
	 */
	if (!ssh_gssapi_oid_table_ok()) 
		ssh_gssapi_server_mechanisms();

	debug2("%s: Identifying %s", __func__, kex->name);
	oid = ssh_gssapi_id_kex(NULL, kex->name, &gex);
	if (oid == NULL)
	   fatal("Unknown gssapi mechanism");

	debug2("%s: Acquiring credentials", __func__);

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctxt, oid))))
        	fatal("Unable to acquire credentials for the server");

	if (gex) {
		debug("Doing group exchange");
		packet_read_expect(SSH2_MSG_KEXGSS_GROUPREQ);
		min = packet_get_int();
		nbits = packet_get_int();
		max = packet_get_int();
		min = MAX(DH_GRP_MIN, min);
		max = MIN(DH_GRP_MAX, max);
		packet_check_eom();
		if (max < min || nbits < min || max < nbits)
			fatal("GSS_GEX, bad parameters: %d !< %d !< %d",
			    min, nbits, max);
		dh = PRIVSEP(choose_dh(min, nbits, max));
		if (dh == NULL)
			packet_disconnect("Protocol error: no matching group found");

		packet_start(SSH2_MSG_KEXGSS_GROUP);
		packet_put_bignum2(dh->p);
		packet_put_bignum2(dh->g);
		packet_send();

		packet_write_wait();
		
	} else {
        	dh = dh_new_group1();
	}
	dh_gen_key(dh, kex->we_need * 8);

	do {
		debug("Wait SSH2_MSG_GSSAPI_INIT");
		type = packet_read();
		switch(type) {
		case SSH2_MSG_KEXGSS_INIT:
			if (dh_client_pub != NULL) 
				fatal("Received KEXGSS_INIT after initialising");
			recv_tok.value = packet_get_string(&slen);
			recv_tok.length = slen; 

			if ((dh_client_pub = BN_new()) == NULL)
				fatal("dh_client_pub == NULL");

			packet_get_bignum2(dh_client_pub);

			/* Send SSH_MSG_KEXGSS_HOSTKEY here, if we want */
			break;
		case SSH2_MSG_KEXGSS_CONTINUE:
			recv_tok.value = packet_get_string(&slen);
			recv_tok.length = slen; 
			break;
		default:
			packet_disconnect(
			    "Protocol error: didn't expect packet type %d",
			    type);
		}

		maj_status = PRIVSEP(ssh_gssapi_accept_ctx(ctxt, &recv_tok, 
		    &send_tok, &ret_flags));

		xfree(recv_tok.value);

		if (maj_status != GSS_S_COMPLETE && send_tok.length == 0)
			fatal("Zero length token output when incomplete");

		if (dh_client_pub == NULL)
			fatal("No client public key");
		
		if (maj_status & GSS_S_CONTINUE_NEEDED) {
			debug("Sending GSSAPI_CONTINUE");
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
			gss_release_buffer(&min_status, &send_tok);
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	if (GSS_ERROR(maj_status)) {
		if (send_tok.length > 0) {
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
		}
		fatal("accept_ctx died");
	}

	if (!(ret_flags & GSS_C_MUTUAL_FLAG))
		fatal("Mutual Authentication flag wasn't set");

	if (!(ret_flags & GSS_C_INTEG_FLAG))
		fatal("Integrity flag wasn't set");
	
	if (!dh_pub_is_valid(dh, dh_client_pub))
		packet_disconnect("bad client public DH value");

	klen = DH_size(dh);
	kbuf = xmalloc(klen); 
	kout = DH_compute_key(kbuf, dh_client_pub, dh);

	shared_secret = BN_new();
	BN_bin2bn(kbuf, kout, shared_secret);
	memset(kbuf, 0, klen);
	xfree(kbuf);

	if (gex) {
		hash = kexgex_hash(
		    kex->client_version_string, kex->server_version_string,
		    buffer_ptr(&kex->peer), buffer_len(&kex->peer),
		    buffer_ptr(&kex->my), buffer_len(&kex->my),
		    NULL, 0,
		    min, nbits, max,
		    dh->p, dh->g,
		    dh_client_pub,
		    dh->pub_key,
		    shared_secret
		);
	}
	else {	
		/* The GSSAPI hash is identical to the Diffie Helman one */
		hash = kex_dh_hash(
		    kex->client_version_string, kex->server_version_string,
		    buffer_ptr(&kex->peer), buffer_len(&kex->peer),
		    buffer_ptr(&kex->my), buffer_len(&kex->my),
		    NULL, 0, /* Change this if we start sending host keys */
		    dh_client_pub, dh->pub_key, shared_secret
		);
	}
	BN_free(dh_client_pub);

	if (kex->session_id == NULL) {
		kex->session_id_len = 20;
		kex->session_id = xmalloc(kex->session_id_len);
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	gssbuf.value = hash;
	gssbuf.length = 20; /* Hashlen appears to always be 20 */

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_sign(ctxt,&gssbuf,&msg_tok))))
		fatal("Couldn't get MIC");

	packet_start(SSH2_MSG_KEXGSS_COMPLETE);
	packet_put_bignum2(dh->pub_key);
	packet_put_string((char *)msg_tok.value,msg_tok.length);

	if (send_tok.length != 0) {
		packet_put_char(1); /* true */
		packet_put_string((char *)send_tok.value, send_tok.length);
	} else {
		packet_put_char(0); /* false */
	}
	packet_send();

	gss_release_buffer(&min_status, &send_tok);
	gss_release_buffer(&min_status, &msg_tok);

	if (gss_kex_context == NULL)
		gss_kex_context = ctxt;
	else 
		ssh_gssapi_delete_ctx(&ctxt);

	DH_free(dh);

	kex_derive_keys(kex, hash, shared_secret);
	BN_clear_free(shared_secret);
	kex_finish(kex);
}
#endif /* GSSAPI */
