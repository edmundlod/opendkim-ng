/*
**  Copyright (c) 2026, The Trusted Domain Project.  All rights reserved.
**
**  t-conformance -- RFC 6376 DKIM conformance test suite
**
**  Tests organized by RFC 6376 section:
**    Section 3.3  - Signing and Verification Algorithms
**    Section 3.4  - Canonicalization
**    Section 3.5  - Signature field tags
**    Section 3.6  - Key management / key records
**    Section 5.4  - Determine the header fields to sign
**    Section 6    - Verifier actions
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <arpa/nameser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* libopendkim includes */
#include "../dkim.h"
#include "../dkim-test.h"
#include "t-testdata.h"

#define MAXHEADER	4096
#define MAXHDRCNT	64

static int tests_run = 0;
static int tests_passed = 0;
static int tests_skipped = 0;

#define CHECK(cond, msg) do { \
	tests_run++; \
	if (!(cond)) { \
		fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
		return 0; \
	} \
	tests_passed++; \
} while(0)

#define SKIP(msg) do { \
	tests_skipped++; \
	printf("  SKIP: %s\n", msg); \
	return 1; \
} while(0)

static void
feed_standard_headers(DKIM *dkim)
{
	if (dkim_header(dkim, HEADER02, strlen(HEADER02)) != DKIM_STAT_OK ||
	    dkim_header(dkim, HEADER03, strlen(HEADER03)) != DKIM_STAT_OK ||
	    dkim_header(dkim, HEADER04, strlen(HEADER04)) != DKIM_STAT_OK ||
	    dkim_header(dkim, HEADER05, strlen(HEADER05)) != DKIM_STAT_OK ||
	    dkim_header(dkim, HEADER06, strlen(HEADER06)) != DKIM_STAT_OK ||
	    dkim_header(dkim, HEADER07, strlen(HEADER07)) != DKIM_STAT_OK ||
	    dkim_header(dkim, HEADER08, strlen(HEADER08)) != DKIM_STAT_OK ||
	    dkim_header(dkim, HEADER09, strlen(HEADER09)) != DKIM_STAT_OK)
		abort();
}

static void
feed_standard_body(DKIM *dkim)
{
	if (dkim_body(dkim, BODY00, strlen(BODY00)) != DKIM_STAT_OK ||
	    dkim_body(dkim, BODY01, strlen(BODY01)) != DKIM_STAT_OK)
		abort();
}

static DKIM_LIB *
make_lib(void)
{
	DKIM_LIB *lib;

	lib = dkim_init(NULL, NULL);
	if (lib == NULL)
		abort();
	return lib;
}

static void
set_fixed_time(DKIM_LIB *lib, uint64_t t)
{
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
	                    &t, sizeof t);
}

static void
set_file_query(DKIM_LIB *lib)
{
	dkim_query_t qtype = DKIM_QUERY_FILE;

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    KEYFILE, strlen(KEYFILE));
}

/* ------------------------------------------------------------------ */
/* RFC 6376 Section 3.3: Signing and Verification Algorithms          */
/* ------------------------------------------------------------------ */

/*
**  3.3.1: RSA-SHA256 verify using RFC 8463 Appendix A test vector
*/

#define RFC8463_KEYFILE  "/tmp/testkeys-rfc8463"
#define RFC8463_DOMAIN   "football.example.com"
#define RFC8463_RSA_SEL  "test"

#define RFC8463_RSA_PUBKEY \
	"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" \
	"KBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi" \
	"Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj" \
	"+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryO" \
	"TIKT+l/K4w3QIDAQAB"

#define RFC8463_SIG_RSA \
	"v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n" \
	" d=football.example.com; i=@football.example.com;\r\n" \
	" q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n" \
	" date : message-id : from : subject : date;\r\n" \
	" bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" \
	" b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n" \
	" DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n" \
	" dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8="

#define RFC8463_HDR_FROM \
	"From: Joe SixPack <joe@football.example.com>"
#define RFC8463_HDR_TO \
	"To: Suzie Q <suzie@shopping.example.net>"
#define RFC8463_HDR_SUBJ \
	"Subject: Is dinner ready?"
#define RFC8463_HDR_DATE \
	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)"
#define RFC8463_HDR_MSGID \
	"Message-ID: <20030712040037.46341.5F8J@football.example.com>"

#define RFC8463_BODY \
	"Hi.\r\n" \
	"\r\n" \
	"We lost the game.  Are you hungry yet?\r\n" \
	"\r\n" \
	"Joe.\r\n"

static int
test_rfc6376_s3_3_rsa_sha256_verify_rfc8463_vector(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	FILE *f;
	unsigned char sighdr[MAXHEADER + 1];

	printf("  RFC6376 3.3: rsa-sha256 verify"
	       " (RFC 8463 Appendix A vector)\n");

	f = fopen(RFC8463_KEYFILE, "w");
	CHECK(f != NULL, "failed to create RFC 8463 key file");
	fprintf(f, "%s._domainkey.%s %s\n",
	        RFC8463_RSA_SEL, RFC8463_DOMAIN, RFC8463_RSA_PUBKEY);
	fclose(f);

	lib = make_lib();
	set_fixed_time(lib, 1528637909);

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    RFC8463_KEYFILE, strlen(RFC8463_KEYFILE));

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "dkim_verify returned NULL");

	snprintf((char *) sighdr, sizeof sighdr, "%s: %s",
	         DKIM_SIGNHEADER, RFC8463_SIG_RSA);
	status = dkim_header(dkim, sighdr, strlen((char *) sighdr));
	CHECK(status == DKIM_STAT_OK, "sig header failed");

	status = dkim_header(dkim, RFC8463_HDR_FROM,
	                     strlen(RFC8463_HDR_FROM));
	CHECK(status == DKIM_STAT_OK, "From header failed");
	status = dkim_header(dkim, RFC8463_HDR_TO,
	                     strlen(RFC8463_HDR_TO));
	CHECK(status == DKIM_STAT_OK, "To header failed");
	status = dkim_header(dkim, RFC8463_HDR_SUBJ,
	                     strlen(RFC8463_HDR_SUBJ));
	CHECK(status == DKIM_STAT_OK, "Subject header failed");
	status = dkim_header(dkim, RFC8463_HDR_DATE,
	                     strlen(RFC8463_HDR_DATE));
	CHECK(status == DKIM_STAT_OK, "Date header failed");
	status = dkim_header(dkim, RFC8463_HDR_MSGID,
	                     strlen(RFC8463_HDR_MSGID));
	CHECK(status == DKIM_STAT_OK, "Message-ID header failed");

	status = dkim_eoh(dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	status = dkim_body(dkim, RFC8463_BODY, strlen(RFC8463_BODY));
	CHECK(status == DKIM_STAT_OK, "body feed failed");

	status = dkim_eom(dkim, NULL);
	CHECK(status == DKIM_STAT_OK,
	      "RFC 8463 RSA-SHA256 test vector verification failed");

	dkim_free(dkim);
	dkim_close(lib);
	(void) remove(RFC8463_KEYFILE);
	return 1;
}

/*
**  3.3.2: rsa-sha256 sign then verify round-trip
*/
static int
test_rfc6376_s3_3_rsa_sha256_roundtrip(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.3: rsa-sha256 sign/verify round-trip\n");

	lib = make_lib();

	if (!dkim_libfeature(lib, DKIM_FEATURE_SHA256))
	{
		dkim_close(lib);
		SKIP("SHA256 not available");
	}

	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "dkim_sign sha256 returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "sha256 sign eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "sha256 sign eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "sha256 getsighdr failed");

	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "sha256 dkim_verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "sha256 verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "sha256 verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "rsa-sha256 round-trip verification failed");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/* ------------------------------------------------------------------ */
/* RFC 6376 Section 3.4: Canonicalization                             */
/* ------------------------------------------------------------------ */

/*
**  3.4.1: All four canonicalization combinations produce valid signatures
*/

static int
test_canon_combo(dkim_canon_t hc, dkim_canon_t bc, const char *label)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.4: %s sign/verify\n", label);

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      hc, bc, DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");

	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "canonicalization round-trip failed");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

static int
test_rfc6376_s3_4_canon_simple_simple(void)
{
	return test_canon_combo(DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                        "simple/simple");
}

static int
test_rfc6376_s3_4_canon_simple_relaxed(void)
{
	return test_canon_combo(DKIM_CANON_SIMPLE, DKIM_CANON_RELAXED,
	                        "simple/relaxed");
}

static int
test_rfc6376_s3_4_canon_relaxed_simple(void)
{
	return test_canon_combo(DKIM_CANON_RELAXED, DKIM_CANON_SIMPLE,
	                        "relaxed/simple");
}

static int
test_rfc6376_s3_4_canon_relaxed_relaxed(void)
{
	return test_canon_combo(DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                        "relaxed/relaxed");
}

/*
**  3.4.2: Relaxed header canonicalization folds whitespace (RFC 6376 3.4.2)
**         Header with extra leading spaces should verify same as normal
*/
static int
test_rfc6376_s3_4_relaxed_hdr_ws_folding(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.4.2: relaxed header WS folding\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_RELAXED, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");

	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	status = dkim_header(vrfy_dkim, HEADER02, strlen(HEADER02));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_header(vrfy_dkim, HEADER03, strlen(HEADER03));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_header(vrfy_dkim, HEADER04, strlen(HEADER04));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_header(vrfy_dkim, HEADER05, strlen(HEADER05));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_header(vrfy_dkim, HEADER06, strlen(HEADER06));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_header(vrfy_dkim, HEADER07XLEADSP, strlen(HEADER07XLEADSP));
	CHECK(status == DKIM_STAT_OK, "header with extra spaces failed");

	status = dkim_header(vrfy_dkim, HEADER08, strlen(HEADER08));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_header(vrfy_dkim, HEADER09, strlen(HEADER09));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_OK,
	      "relaxed header WS folding should not affect verification");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.4.3: Simple header canonicalization is strict -- extra WS breaks sig
*/
static int
test_rfc6376_s3_4_simple_hdr_ws_strict(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.4.1: simple header canonicalization is strict\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");

	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	status = dkim_header(vrfy_dkim, HEADER02, strlen(HEADER02));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER03, strlen(HEADER03));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER04, strlen(HEADER04));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER05, strlen(HEADER05));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER06, strlen(HEADER06));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_header(vrfy_dkim, HEADER07XLEADSP,
	                     strlen(HEADER07XLEADSP));
	CHECK(status == DKIM_STAT_OK, "header with extra WS accepted");

	status = dkim_header(vrfy_dkim, HEADER08, strlen(HEADER08));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER09, strlen(HEADER09));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_BADSIG,
	      "simple canon must reject modified headers");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.4.4: Relaxed body canonicalization collapses trailing empty lines
**         and trailing whitespace on lines
*/
static int
test_rfc6376_s3_4_relaxed_body_trailing(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.4.4: relaxed body trailing empty lines\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	status = dkim_body(sign_dkim, BODY00, strlen(BODY00));
	CHECK(status == DKIM_STAT_OK, "body failed");

	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	status = dkim_body(vrfy_dkim, BODY00, strlen(BODY00));
	CHECK(status == DKIM_STAT_OK, "body failed");

	status = dkim_body(vrfy_dkim, BODY03, strlen(BODY03));
	CHECK(status == DKIM_STAT_OK, "extra blank line");
	status = dkim_body(vrfy_dkim, BODY03, strlen(BODY03));
	CHECK(status == DKIM_STAT_OK, "extra blank line");

	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_OK,
	      "relaxed body must ignore trailing empty lines");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.4.5: CRLF fixing: non-standard line endings normalized
*/
static int
test_rfc6376_s3_4_crlf_fixing(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	u_int flags;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.4: CRLF normalization (FIXCRLF)\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);

	(void) dkim_options(lib, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS,
	                    &flags, sizeof flags);
	flags |= DKIM_LIBFLAGS_FIXCRLF;
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
	                    &flags, sizeof flags);

	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	status = dkim_body(sign_dkim, NBODY00, strlen(NBODY00));
	CHECK(status == DKIM_STAT_OK, "body with bare LF failed");

	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom with FIXCRLF failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");

	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	status = dkim_body(vrfy_dkim, NBODY00, strlen(NBODY00));
	CHECK(status == DKIM_STAT_OK, "verify body failed");

	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "CRLF fixed body should verify");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/* ------------------------------------------------------------------ */
/* RFC 6376 Section 3.5: The DKIM-Signature Header Field              */
/* ------------------------------------------------------------------ */

/*
**  3.5.1: Signature v= MUST be "1" (Section 3.5)
*/
static int
test_rfc6376_s3_5_version_must_be_1(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	unsigned char hdr[MAXHEADER + 1];

#define SIG_BADVERSION "v=2; a=rsa-sha1; c=simple/simple; d=example.com; " \
	"s=test; t=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; " \
	"h=Received:From:To:Date:Subject:Message-ID; b=AAAA"

	printf("  RFC6376 3.5: v= tag MUST be \"1\"\n");

	lib = make_lib();
	set_file_query(lib);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "verify returned NULL");

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG_BADVERSION);
	status = dkim_header(dkim, hdr, strlen(hdr));
	CHECK(status == DKIM_STAT_OK, "header parse failed");

	feed_standard_headers(dkim);
	status = dkim_eoh(dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(dkim);
	status = dkim_eom(dkim, NULL);
	CHECK(status == DKIM_STAT_CANTVRFY,
	      "bad version must result in CANTVRFY");

	sig = dkim_getsignature(dkim);
	CHECK(sig != NULL, "no signature handle returned");
	CHECK(dkim_sig_geterror(sig) == DKIM_SIGERROR_VERSION,
	      "error must be SIGERROR_VERSION");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.5.2: Missing required tags (d=, s=, b=, bh=, h=) produce errors
*/
static int
test_rfc6376_s3_5_missing_required_tags(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	int nsigs;
	u_int flags;
	DKIM_SIGINFO **sigs;
	unsigned char hdr[MAXHEADER + 1];

#define SIG_NO_S "v=1; a=rsa-sha1; c=relaxed; d=example.com; " \
	"t=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; " \
	"h=From:To:Date:Subject; b=AAAA"
#define SIG_NO_V "a=rsa-sha1; c=relaxed; d=example.com; s=test; " \
	"t=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; " \
	"h=From:To:Date:Subject; b=AAAA"

	printf("  RFC6376 3.5: missing required tags (s=, v=)\n");

	lib = make_lib();
	set_file_query(lib);

	flags = DKIM_LIBFLAGS_BADSIGHANDLES;
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
	                    &flags, sizeof flags);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "verify returned NULL");

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG_NO_S);
	status = dkim_header(dkim, hdr, strlen(hdr));
	CHECK(status == DKIM_STAT_SYNTAX, "missing s= not detected as SYNTAX");

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG_NO_V);
	status = dkim_header(dkim, hdr, strlen(hdr));
	CHECK(status == DKIM_STAT_SYNTAX, "missing v= not detected as SYNTAX");

	feed_standard_headers(dkim);
	status = dkim_eoh(dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	status = dkim_getsiglist(dkim, &sigs, &nsigs);
	CHECK(status == DKIM_STAT_OK, "getsiglist failed");
	CHECK(nsigs == 2, "expected 2 bad signatures");
	CHECK(dkim_sig_geterror(sigs[0]) == DKIM_SIGERROR_MISSING_S,
	      "first sig should have MISSING_S error");
	CHECK(dkim_sig_geterror(sigs[1]) == DKIM_SIGERROR_MISSING_V,
	      "second sig should have MISSING_V error");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.5.3: Signature expiration (x= tag) -- expired sig must fail
*/
static int
test_rfc6376_s3_5_expiration(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	dkim_sigkey_t key;
	uint64_t sigttl;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.5: signature expiration (x= tag)\n");

	lib = make_lib();

	set_fixed_time(lib, 1172620939);

	sigttl = 60;
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNATURETTL,
	                    &sigttl, sizeof sigttl);

	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	dkim_free(sign_dkim);

	set_fixed_time(lib, 1172620939 + 3600);
	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);

	sig = dkim_getsignature(vrfy_dkim);
	CHECK(sig != NULL, "no signature returned");
	CHECK(dkim_sig_geterror(sig) == DKIM_SIGERROR_EXPIRED,
	      "expired sig must produce SIGERROR_EXPIRED");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.5.4: Body length tag (l=) -- extra data after l= limit is OK
*/
static int
test_rfc6376_s3_5_body_length(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	u_int flags;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.5: body length tag (l=)\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);

	(void) dkim_options(lib, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS,
	                    &flags, sizeof flags);
	flags |= DKIM_LIBFLAGS_SIGNLEN;
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
	                    &flags, sizeof flags);

	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");

	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);

	status = dkim_body(vrfy_dkim, BODY06, strlen(BODY06));
	CHECK(status == DKIM_STAT_OK, "extra body beyond l= failed");

	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_OK,
	      "data beyond l= limit must not break verification");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/* ------------------------------------------------------------------ */
/* RFC 6376 Section 3.6.1: Key records                                */
/* ------------------------------------------------------------------ */

/*
**  3.6.1a: Key with bad version in DNS record
*/
static int
test_rfc6376_s3_6_key_bad_version(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.6.1: key with bad version\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTORBADV, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);

	sig = dkim_getsignature(vrfy_dkim);
	CHECK(sig != NULL, "no signature handle returned");
	CHECK(dkim_sig_geterror(sig) == DKIM_SIGERROR_KEYVERSION,
	      "bad key version must produce SIGERROR_KEYVERSION");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.6.1b: Key with unknown key type
*/
static int
test_rfc6376_s3_6_key_bad_type(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.6.1: key with unknown key type (k=xxx)\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTORBADK, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);

	sig = dkim_getsignature(vrfy_dkim);
	CHECK(sig != NULL, "no signature handle returned");
	CHECK(dkim_sig_geterror(sig) == DKIM_SIGERROR_KEYTYPEUNKNOWN,
	      "unknown key type must produce SIGERROR_KEYTYPEUNKNOWN");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.6.1c: Key with revoked key (empty p= tag)
*/
static int
test_rfc6376_s3_6_key_revoked(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.6.1: revoked key (empty p=)\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOREMPTYP, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_REVOKED,
	      "empty p= must produce DKIM_STAT_REVOKED");

	sig = dkim_getsignature(vrfy_dkim);
	CHECK(sig != NULL, "no signature handle returned");
	CHECK(dkim_sig_geterror(sig) == DKIM_SIGERROR_KEYREVOKED,
	      "empty p= must produce SIGERROR_KEYREVOKED");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  3.6.1d: Key with unsupported hash (h= in key record)
*/
static int
test_rfc6376_s3_6_key_bad_hash(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 3.6.1: key with unsupported hash\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTORBADH, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);

	sig = dkim_getsignature(vrfy_dkim);
	CHECK(sig != NULL, "no signature handle returned");
	CHECK(dkim_sig_geterror(sig) == DKIM_SIGERROR_KEYUNKNOWNHASH,
	      "bad key hash must produce SIGERROR_KEYUNKNOWNHASH");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/* ------------------------------------------------------------------ */
/* RFC 6376 Section 5.4: Determine the header fields to sign          */
/* ------------------------------------------------------------------ */

/*
**  5.4.1: From: MUST be signed (it is in the default list)
*/
static int
test_rfc6376_s5_4_from_must_be_signed(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 5.4: From: header MUST be signed\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(dkim != NULL, "sign returned NULL");

	feed_standard_headers(dkim);
	status = dkim_eoh(dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(dkim);
	status = dkim_eom(dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");

	CHECK(strstr(hdr, "From") != NULL,
	      "From must appear in the h= list of signed headers");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/* ------------------------------------------------------------------ */
/* RFC 6376 Section 6: Verifier Actions                               */
/* ------------------------------------------------------------------ */

/*
**  6.1.1: No signature on message must return DKIM_STAT_NOSIG
*/
static int
test_rfc6376_s6_no_signature(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;

	printf("  RFC6376 6.1: no signature returns NOSIG\n");

	lib = make_lib();

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "verify returned NULL");

	feed_standard_headers(dkim);

	status = dkim_eoh(dkim);
	CHECK(status == DKIM_STAT_NOSIG,
	      "message with no sig must return DKIM_STAT_NOSIG at eoh");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  6.1.2: Tampered body must fail verification
*/
static int
test_rfc6376_s6_tampered_body(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 6.1: tampered body must fail\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	{
		const char *tampered = "This body has been tampered with.\r\n";
		status = dkim_body(vrfy_dkim, (u_char *) tampered, strlen(tampered));
		CHECK(status == DKIM_STAT_OK, "tampered body feed failed");
	}

	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_BADSIG,
	      "tampered body must result in DKIM_STAT_BADSIG");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  6.1.3: Tampered header must fail with simple canonicalization
*/
static int
test_rfc6376_s6_tampered_header(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC6376 6.1: tampered header must fail (simple)\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "verify sig header failed");
	}

	status = dkim_header(vrfy_dkim, HEADER02, strlen(HEADER02));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER03, strlen(HEADER03));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER04, strlen(HEADER04));
	CHECK(status == DKIM_STAT_OK, "header failed");

	{
		const char *tampered_from =
			"From: TAMPERED <evil@attacker.com>";
		status = dkim_header(vrfy_dkim, (u_char *) tampered_from,
		                     strlen(tampered_from));
		CHECK(status == DKIM_STAT_OK, "tampered From accepted by parser");
	}

	status = dkim_header(vrfy_dkim, HEADER06, strlen(HEADER06));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER07, strlen(HEADER07));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER08, strlen(HEADER08));
	CHECK(status == DKIM_STAT_OK, "header failed");
	status = dkim_header(vrfy_dkim, HEADER09, strlen(HEADER09));
	CHECK(status == DKIM_STAT_OK, "header failed");

	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_BADSIG,
	      "tampered From header must result in DKIM_STAT_BADSIG");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  6.1.4: Multiple signatures -- all processed
*/
static int
test_rfc6376_s6_multiple_signatures(void)
{
	DKIM_STAT status;
	DKIM *sign1, *sign2, *vrfy;
	DKIM_LIB *lib;
	int nsigs;
	DKIM_SIGINFO **sigs;
	dkim_sigkey_t key;
	unsigned char hdr1[MAXHEADER + 1];
	unsigned char hdr2[MAXHEADER + 1];

	printf("  RFC6376 6.1: multiple signatures both processed\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign1 = dkim_sign(lib, "sig1", NULL, key, SELECTOR, DOMAIN,
	                  DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                  DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign1 != NULL, "sign1 returned NULL");

	feed_standard_headers(sign1);
	dkim_eoh(sign1);
	feed_standard_body(sign1);
	dkim_eom(sign1, NULL);

	memset(hdr1, '\0', sizeof hdr1);
	dkim_getsighdr(sign1, hdr1, sizeof hdr1,
	               strlen(DKIM_SIGNHEADER) + 2);
	dkim_free(sign1);

	sign2 = dkim_sign(lib, "sig2", NULL, key, SELECTOR, DOMAIN,
	                  DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                  DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign2 != NULL, "sign2 returned NULL");

	feed_standard_headers(sign2);
	dkim_eoh(sign2);
	feed_standard_body(sign2);
	dkim_eom(sign2, NULL);

	memset(hdr2, '\0', sizeof hdr2);
	dkim_getsighdr(sign2, hdr2, sizeof hdr2,
	               strlen(DKIM_SIGNHEADER) + 2);
	dkim_free(sign2);

	set_file_query(lib);

	vrfy = dkim_verify(lib, "vrfy", NULL, &status);
	CHECK(vrfy != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];

		snprintf(inhdr, sizeof inhdr, "%s: %s",
		         DKIM_SIGNHEADER, hdr1);
		status = dkim_header(vrfy, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "sig1 header failed");

		snprintf(inhdr, sizeof inhdr, "%s: %s",
		         DKIM_SIGNHEADER, hdr2);
		status = dkim_header(vrfy, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "sig2 header failed");
	}

	feed_standard_headers(vrfy);
	status = dkim_eoh(vrfy);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy);
	status = dkim_eom(vrfy, NULL);
	CHECK(status == DKIM_STAT_OK, "verify eom failed");

	status = dkim_getsiglist(vrfy, &sigs, &nsigs);
	CHECK(status == DKIM_STAT_OK, "getsiglist failed");
	CHECK(nsigs == 2, "expected 2 signatures to be processed");

	dkim_free(vrfy);
	dkim_close(lib);
	return 1;
}

/* ------------------------------------------------------------------ */
/* API conformance tests                                              */
/* ------------------------------------------------------------------ */

/*
**  API 1: dkim_init / dkim_close lifecycle
*/
static int
test_api_init_close(void)
{
	DKIM_LIB *lib;

	printf("  API: dkim_init / dkim_close lifecycle\n");

	lib = dkim_init(NULL, NULL);
	CHECK(lib != NULL, "dkim_init must not return NULL");

	dkim_close(lib);
	return 1;
}

/*
**  API 2: dkim_getmode returns correct mode
*/
static int
test_api_getmode(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;

	printf("  API: dkim_getmode returns correct mode\n");

	lib = make_lib();
	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(dkim != NULL, "sign returned NULL");
	CHECK(dkim_getmode(dkim) == DKIM_MODE_SIGN,
	      "signing handle must report DKIM_MODE_SIGN");
	dkim_free(dkim);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "verify returned NULL");
	CHECK(dkim_getmode(dkim) == DKIM_MODE_VERIFY,
	      "verifying handle must report DKIM_MODE_VERIFY");
	dkim_free(dkim);

	dkim_close(lib);
	return 1;
}

/*
**  API 3: dkim_getid returns the ID
*/
static int
test_api_getid(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;

	printf("  API: dkim_getid returns correct ID\n");

	lib = make_lib();
	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(dkim != NULL, "sign returned NULL");
	CHECK(strcmp(dkim_getid(dkim), JOBID) == 0,
	      "dkim_getid must return the ID passed to dkim_sign");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 4: dkim_set_margin / dkim_getpartial / dkim_setpartial
*/
static int
test_api_margin_and_partial(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;

	printf("  API: margin and partial body length tag\n");

	lib = make_lib();
	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(dkim != NULL, "sign returned NULL");

	status = dkim_set_margin(dkim, 0);
	CHECK(status == DKIM_STAT_OK,
	      "dkim_set_margin(0) on signing handle must succeed");

	status = dkim_set_margin(dkim, 80);
	CHECK(status == DKIM_STAT_OK,
	      "dkim_set_margin(80) on signing handle must succeed");

	CHECK(dkim_getpartial(dkim) == 0,
	      "partial should default to false");

	status = dkim_setpartial(dkim, 1);
	CHECK(status == DKIM_STAT_OK, "setpartial must succeed");
	CHECK(dkim_getpartial(dkim) == 1,
	      "partial should now be true");

	dkim_free(dkim);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "verify returned NULL");

	status = dkim_set_margin(dkim, 0);
	CHECK(status == DKIM_STAT_INVALID,
	      "dkim_set_margin on verify handle must return INVALID");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 5: dkim_set_signer / dkim_get_signer
*/
static int
test_api_signer(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;

	printf("  API: dkim_set_signer / dkim_get_signer\n");

	lib = make_lib();
	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(dkim != NULL, "sign returned NULL");

	status = dkim_set_signer(dkim, "user@example.com");
	CHECK(status == DKIM_STAT_OK, "set_signer must succeed");

	CHECK(strcmp(dkim_get_signer(dkim), "user@example.com") == 0,
	      "get_signer must return the set value");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 6: dkim_set_user_context / dkim_get_user_context
*/
static int
test_api_user_context(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	int ctx_data = 42;

	printf("  API: user context get/set\n");

	lib = make_lib();
	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(dkim != NULL, "sign returned NULL");

	CHECK(dkim_get_user_context(dkim) == NULL,
	      "initial user context must be NULL");

	status = dkim_set_user_context(dkim, &ctx_data);
	CHECK(status == DKIM_STAT_OK, "set_user_context must succeed");

	CHECK(dkim_get_user_context(dkim) == &ctx_data,
	      "get_user_context must return the pointer we set");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 7: dkim_getresultstr returns known strings
*/
static int
test_api_getresultstr(void)
{
	printf("  API: dkim_getresultstr for known codes\n");

	CHECK(dkim_getresultstr(DKIM_STAT_OK) != NULL,
	      "result string for OK must not be NULL");
	CHECK(dkim_getresultstr(DKIM_STAT_BADSIG) != NULL,
	      "result string for BADSIG must not be NULL");
	CHECK(dkim_getresultstr(DKIM_STAT_NOSIG) != NULL,
	      "result string for NOSIG must not be NULL");
	CHECK(dkim_getresultstr(DKIM_STAT_NOKEY) != NULL,
	      "result string for NOKEY must not be NULL");
	CHECK(dkim_getresultstr(DKIM_STAT_REVOKED) != NULL,
	      "result string for REVOKED must not be NULL");
	CHECK(dkim_getresultstr(DKIM_STAT_INTERNAL) != NULL,
	      "result string for INTERNAL must not be NULL");

	return 1;
}

/*
**  API 8: dkim_sig_geterrorstr for known error codes
*/
static int
test_api_sig_geterrorstr(void)
{
	printf("  API: dkim_sig_geterrorstr for known codes\n");

	CHECK(dkim_sig_geterrorstr(DKIM_SIGERROR_OK) != NULL,
	      "error string for SIGERROR_OK must not be NULL");
	CHECK(dkim_sig_geterrorstr(DKIM_SIGERROR_VERSION) != NULL,
	      "error string for VERSION must not be NULL");
	CHECK(dkim_sig_geterrorstr(DKIM_SIGERROR_DOMAIN) != NULL,
	      "error string for DOMAIN must not be NULL");
	CHECK(dkim_sig_geterrorstr(DKIM_SIGERROR_EXPIRED) != NULL,
	      "error string for EXPIRED must not be NULL");
	CHECK(dkim_sig_geterrorstr(DKIM_SIGERROR_MISSING_S) != NULL,
	      "error string for MISSING_S must not be NULL");
	CHECK(dkim_sig_geterrorstr(DKIM_SIGERROR_BADSIG) != NULL,
	      "error string for BADSIG must not be NULL");
	CHECK(dkim_sig_geterrorstr(DKIM_SIGERROR_KEYREVOKED) != NULL,
	      "error string for KEYREVOKED must not be NULL");

	return 1;
}

/*
**  API 9: dkim_libversion returns sane value
*/
static int
test_api_libversion(void)
{
	uint32_t ver;

	printf("  API: dkim_libversion\n");

	ver = dkim_libversion();
	CHECK(ver == OPENDKIM_LIB_VERSION,
	      "dkim_libversion must match OPENDKIM_LIB_VERSION");

	return 1;
}

/*
**  API 10: dkim_libfeature checks
*/
static int
test_api_libfeature(void)
{
	DKIM_LIB *lib;

	printf("  API: dkim_libfeature checks\n");

	lib = make_lib();

	CHECK(dkim_libfeature(lib, DKIM_FEATURE_MAX + 1) == 0,
	      "out-of-range feature must return false");

	dkim_close(lib);
	return 1;
}

/*
**  API 11: dkim_sig_syntax on valid and invalid signature strings
*/
static int
test_api_sig_syntax(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;

	printf("  API: dkim_sig_syntax validation\n");

	lib = make_lib();
	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "verify returned NULL");

	{
		const char *valid_sig =
			"v=1; a=rsa-sha1; d=example.com; s=test; "
			"h=From:To; bh=AAAA; b=AAAA";
		status = dkim_sig_syntax(dkim, (u_char *) valid_sig,
		                         strlen(valid_sig));
		CHECK(status == DKIM_STAT_OK,
		      "valid sig syntax must return OK");
	}

	{
		const char *bad_sig = "GARBAGE DATA NOT A SIGNATURE";
		status = dkim_sig_syntax(dkim, (u_char *) bad_sig,
		                         strlen(bad_sig));
		CHECK(status == DKIM_STAT_SYNTAX,
		      "invalid sig must return SYNTAX");
	}

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 12: dkim_key_syntax on valid and invalid key strings
*/
static int
test_api_key_syntax(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;

	printf("  API: dkim_key_syntax validation\n");

	lib = make_lib();
	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "verify returned NULL");

	{
		const char *valid_key = "v=DKIM1; k=rsa; p=MIGfMA0G";
		status = dkim_key_syntax(dkim, (u_char *) valid_key,
		                         strlen(valid_key));
		CHECK(status == DKIM_STAT_OK,
		      "valid key syntax must return OK");
	}

	{
		const char *bad_key = "GARBAGE NOT A KEY RECORD";
		status = dkim_key_syntax(dkim, (u_char *) bad_key,
		                         strlen(bad_key));
		CHECK(status == DKIM_STAT_SYNTAX,
		      "invalid key must return SYNTAX");
	}

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 13: dkim_options get/set round-trip
*/
static int
test_api_options(void)
{
	DKIM_STAT status;
	DKIM_LIB *lib;
	u_int flags_in, flags_out;
	uint64_t time_in, time_out;

	printf("  API: dkim_options get/set round-trip\n");

	lib = make_lib();

	flags_in = DKIM_LIBFLAGS_SIGNLEN | DKIM_LIBFLAGS_ZTAGS;
	status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
	                      &flags_in, sizeof flags_in);
	CHECK(status == DKIM_STAT_OK, "setopt FLAGS failed");

	flags_out = 0;
	status = dkim_options(lib, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS,
	                      &flags_out, sizeof flags_out);
	CHECK(status == DKIM_STAT_OK, "getopt FLAGS failed");
	CHECK(flags_out == flags_in, "FLAGS round-trip must match");

	time_in = 1234567890;
	status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
	                      &time_in, sizeof time_in);
	CHECK(status == DKIM_STAT_OK, "setopt FIXEDTIME failed");

	time_out = 0;
	status = dkim_options(lib, DKIM_OP_GETOPT, DKIM_OPTS_FIXEDTIME,
	                      &time_out, sizeof time_out);
	CHECK(status == DKIM_STAT_OK, "getopt FIXEDTIME failed");
	CHECK(time_out == time_in, "FIXEDTIME round-trip must match");

	dkim_close(lib);
	return 1;
}

/*
**  API 14: dkim_mail_parse extracts user and domain
*/
static int
test_api_mail_parse(void)
{
	int ret;
	u_char *user, *domain;

	printf("  API: dkim_mail_parse\n");

	{
		u_char addr[] = "user@example.com";
		ret = dkim_mail_parse(addr, &user, &domain);
		CHECK(ret == 0, "mail_parse must return 0");
		CHECK(strcmp(user, "user") == 0, "user must be 'user'");
		CHECK(strcmp(domain, "example.com") == 0,
		      "domain must be 'example.com'");
	}

	{
		u_char addr[] = "<user@example.com>";
		ret = dkim_mail_parse(addr, &user, &domain);
		CHECK(ret == 0, "mail_parse with angle brackets must return 0");
		CHECK(strcmp(user, "user") == 0, "user must be 'user'");
		CHECK(strcmp(domain, "example.com") == 0,
		      "domain must be 'example.com'");
	}

	return 1;
}

/*
**  API 15: dkim_qp_decode
*/
static int
test_api_qp_decode(void)
{
	int ret;
	unsigned char input[] = "=5BDKIM=20error=5D";
	unsigned char output[64];

	printf("  API: dkim_qp_decode\n");

	ret = dkim_qp_decode(input, output, sizeof output);
	CHECK(ret > 0, "qp_decode must return positive byte count");
	CHECK(strcmp(output, SMTPTOKEN) == 0,
	      "decoded QP must match expected string");

	return 1;
}

/*
**  API 16: dkim_sig_getcanons / dkim_sig_getdomain / dkim_sig_getselector
*/
static int
test_api_sig_accessors(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	dkim_sigkey_t key;
	dkim_canon_t hc, bc;
	unsigned char hdr[MAXHEADER + 1];

	printf("  API: sig accessors (getcanons, getdomain, getselector)\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_RELAXED, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	feed_standard_headers(sign_dkim);
	dkim_eoh(sign_dkim);
	feed_standard_body(sign_dkim);
	dkim_eom(sign_dkim, NULL);

	memset(hdr, '\0', sizeof hdr);
	dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	               strlen(DKIM_SIGNHEADER) + 2);
	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
	}

	feed_standard_headers(vrfy_dkim);
	dkim_eoh(vrfy_dkim);
	feed_standard_body(vrfy_dkim);
	dkim_eom(vrfy_dkim, NULL);

	sig = dkim_getsignature(vrfy_dkim);
	CHECK(sig != NULL, "no signature returned");

	status = dkim_sig_getcanons(sig, &hc, &bc);
	CHECK(status == DKIM_STAT_OK, "getcanons failed");
	CHECK(hc == DKIM_CANON_RELAXED, "header canon must be relaxed");
	CHECK(bc == DKIM_CANON_SIMPLE, "body canon must be simple");

	CHECK(strcmp(dkim_sig_getdomain(sig), DOMAIN) == 0,
	      "getdomain must return " DOMAIN);
	CHECK(strcmp(dkim_sig_getselector(sig), SELECTOR) == 0,
	      "getselector must return " SELECTOR);

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 17: dkim_minbody
*/
static int
test_api_minbody(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	unsigned char hdr[MAXHEADER + 1];

#define SIG_WITH_L "v=1; a=rsa-sha1; c=relaxed/relaxed; d=example.com; " \
	"s=test; t=1172620939; bh=Z9ONHHsBrKN0pbfrOu025VfbdR4=; l=340; " \
	"h=Received:Received:Received:From:To:Date:Subject:Message-ID; " \
	"b=AAAA"

	printf("  API: dkim_minbody\n");

	lib = make_lib();
	set_file_query(lib);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "verify returned NULL");

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG_WITH_L);
	dkim_header(dkim, hdr, strlen(hdr));

	feed_standard_headers(dkim);
	dkim_eoh(dkim);

	CHECK(dkim_minbody(dkim) == 340,
	      "minbody must return l= value after eoh");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 18: dkim_getsighdr_d dynamic allocation
*/
static int
test_api_getsighdr_d(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	u_char *buf = NULL;
	size_t len = 0;

	printf("  API: dkim_getsighdr_d dynamic allocation\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(dkim != NULL, "sign returned NULL");

	feed_standard_headers(dkim);
	dkim_eoh(dkim);
	feed_standard_body(dkim);
	dkim_eom(dkim, NULL);

	status = dkim_getsighdr_d(dkim, strlen(DKIM_SIGNHEADER) + 2,
	                          &buf, &len);
	CHECK(status == DKIM_STAT_OK, "getsighdr_d failed");
	CHECK(buf != NULL, "getsighdr_d must return non-NULL buffer");
	CHECK(len > 0, "getsighdr_d must return positive length");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 19: extension tags (dkim_add_xtag)
*/
static int
test_api_xtag(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  API: dkim_add_xtag\n");

	lib = make_lib();

	if (!dkim_libfeature(lib, DKIM_FEATURE_XTAGS))
	{
		dkim_close(lib);
		SKIP("XTAGS feature not available");
	}

	set_fixed_time(lib, 1172620939);
	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(dkim != NULL, "sign returned NULL");

	status = dkim_add_xtag(dkim, "foo", "bar");
	CHECK(status == DKIM_STAT_OK, "add_xtag must succeed");

	feed_standard_headers(dkim);
	dkim_eoh(dkim);
	feed_standard_body(dkim);
	status = dkim_eom(dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom with xtag failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr failed");
	CHECK(strstr(hdr, "foo=bar") != NULL,
	      "extension tag must appear in signature");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

/*
**  API 20: dkim_chunk interface
*/
static int
test_api_chunk(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("  API: dkim_chunk interface\n");

	lib = make_lib();
	set_fixed_time(lib, 1172620939);
	key = KEY;

	sign_dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                      DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
	                      DKIM_SIGN_RSASHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "sign returned NULL");

	{
		const char *msg =
			HEADER02 "\r\n"
			HEADER05 "\r\n"
			HEADER07 "\r\n"
			HEADER08 "\r\n"
			"\r\n"
			BODY00;

		status = dkim_chunk(sign_dkim, (u_char *) msg, strlen(msg));
		CHECK(status == DKIM_STAT_OK, "chunk sign failed");

		status = dkim_chunk(sign_dkim, NULL, 0);
		CHECK(status == DKIM_STAT_OK, "chunk finalize failed");
	}

	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "eom after chunk failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "getsighdr after chunk failed");

	dkim_free(sign_dkim);

	set_file_query(lib);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "verify returned NULL");

	{
		unsigned char msg[MAXHEADER * 4];
		snprintf(msg, sizeof msg,
		         "%s: %s\r\n"
		         "%s\r\n"
		         "%s\r\n"
		         "%s\r\n"
		         "%s\r\n"
		         "\r\n"
		         "%s",
		         DKIM_SIGNHEADER, hdr,
		         HEADER02, HEADER05, HEADER07, HEADER08,
		         BODY00);

		status = dkim_chunk(vrfy_dkim, msg, strlen(msg));
		CHECK(status == DKIM_STAT_OK, "chunk verify failed");

		status = dkim_chunk(vrfy_dkim, NULL, 0);
		CHECK(status == DKIM_STAT_OK, "chunk verify finalize failed");
	}

	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "chunk round-trip verification failed");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	return 1;
}

/*
**  RFC 8463 Ed25519 conformance tests
*/

#define RFC8463_ED_SEL		"brisbane"
#define RFC8463_ED_PRIVKEY_FILE	"/tmp/testkeys-rfc8463-ed25519.pem"
#define RFC8463_ED_KEYNAME	"brisbane._domainkey.football.example.com"

#define RFC8463_ED_PRIVKEY_PEM \
	"-----BEGIN PRIVATE KEY-----\n" \
	"MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n" \
	"-----END PRIVATE KEY-----\n"

#define RFC8463_ED_PUBKEY \
	"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

#define RFC8463_ED_SIG \
	"v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n" \
	" d=football.example.com; i=@football.example.com;\r\n" \
	" q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n" \
	" subject : date : message-id : from : subject : date;\r\n" \
	" bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" \
	" b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n" \
	" Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw=="

static int
test_rfc8463_ed25519_verify_rfc_vector(void)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	int i;
	unsigned char sighdr[MAXHEADER + 1];

	printf("  RFC8463: ed25519 verify (Appendix A vector)\n");

	lib = make_lib();
	set_fixed_time(lib, 1528637909);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(dkim != NULL, "dkim_verify returned NULL");

	snprintf((char *) sighdr, sizeof sighdr, "%s: %s",
	         DKIM_SIGNHEADER, RFC8463_ED_SIG);
	status = dkim_header(dkim, sighdr, strlen((char *) sighdr));
	CHECK(status == DKIM_STAT_OK, "sig header failed");

	status = dkim_header(dkim, RFC8463_HDR_FROM, strlen(RFC8463_HDR_FROM));
	CHECK(status == DKIM_STAT_OK, "From header failed");
	status = dkim_header(dkim, RFC8463_HDR_TO, strlen(RFC8463_HDR_TO));
	CHECK(status == DKIM_STAT_OK, "To header failed");
	status = dkim_header(dkim, RFC8463_HDR_SUBJ, strlen(RFC8463_HDR_SUBJ));
	CHECK(status == DKIM_STAT_OK, "Subject header failed");
	status = dkim_header(dkim, RFC8463_HDR_DATE, strlen(RFC8463_HDR_DATE));
	CHECK(status == DKIM_STAT_OK, "Date header failed");
	status = dkim_header(dkim, RFC8463_HDR_MSGID, strlen(RFC8463_HDR_MSGID));
	CHECK(status == DKIM_STAT_OK, "Message-ID header failed");

	for (i = 0; i < 4; i++)
	{
		status = dkim_test_dns_put(dkim, C_IN, T_TXT, 0,
		                           (u_char *) RFC8463_ED_KEYNAME,
		                           (u_char *) RFC8463_ED_PUBKEY);
		CHECK(status == 0, "failed to inject ed25519 DNS key");
	}

	status = dkim_eoh(dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	status = dkim_body(dkim, RFC8463_BODY, strlen(RFC8463_BODY));
	CHECK(status == DKIM_STAT_OK, "body feed failed");

	status = dkim_eom(dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "RFC 8463 Ed25519 verification failed");

	dkim_free(dkim);
	dkim_close(lib);
	return 1;
}

static int
test_rfc8463_ed25519_roundtrip(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	int i;
	unsigned char hdr[MAXHEADER + 1];
	FILE *f;

	printf("  RFC8463: ed25519 sign/verify round-trip\n");

	f = fopen(RFC8463_ED_PRIVKEY_FILE, "w");
	CHECK(f != NULL, "failed to create Ed25519 private key file");
	fprintf(f, "%s", RFC8463_ED_PRIVKEY_PEM);
	fclose(f);

	lib = make_lib();
	set_fixed_time(lib, 1528637909);

	sign_dkim = dkim_sign(lib, JOBID, NULL, (dkim_sigkey_t) RFC8463_ED_PRIVKEY_PEM,
	                      RFC8463_ED_SEL, RFC8463_DOMAIN,
	                      DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                      DKIM_SIGN_ED25519SHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "ed25519 dkim_sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "ed25519 sign eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "ed25519 sign eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "ed25519 getsighdr failed");
	dkim_free(sign_dkim);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "ed25519 dkim_verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "ed25519 verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	for (i = 0; i < 4; i++)
	{
		status = dkim_test_dns_put(vrfy_dkim, C_IN, T_TXT, 0,
		                           (u_char *) RFC8463_ED_KEYNAME,
		                           (u_char *) RFC8463_ED_PUBKEY);
		CHECK(status == 0, "failed to inject ed25519 DNS key");
	}

	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "ed25519 verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "ed25519 round-trip verification failed");

	dkim_free(vrfy_dkim);
	dkim_close(lib);
	(void) remove(RFC8463_ED_PRIVKEY_FILE);
	return 1;
}

static int
test_rfc8463_ed25519_wrong_keytype(void)
{
	DKIM_STAT status;
	DKIM *sign_dkim, *vrfy_dkim;
	DKIM_LIB *lib;
	int i;
	unsigned char hdr[MAXHEADER + 1];

	printf("  RFC8463: ed25519 verification rejects k=rsa key record\n");

	lib = make_lib();
	set_fixed_time(lib, 1528637909);

	sign_dkim = dkim_sign(lib, JOBID, NULL, (dkim_sigkey_t) RFC8463_ED_PRIVKEY_PEM,
	                      RFC8463_ED_SEL, RFC8463_DOMAIN,
	                      DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                      DKIM_SIGN_ED25519SHA256, -1L, &status);
	CHECK(sign_dkim != NULL, "ed25519 dkim_sign returned NULL");

	feed_standard_headers(sign_dkim);
	status = dkim_eoh(sign_dkim);
	CHECK(status == DKIM_STAT_OK, "ed25519 sign eoh failed");

	feed_standard_body(sign_dkim);
	status = dkim_eom(sign_dkim, NULL);
	CHECK(status == DKIM_STAT_OK, "ed25519 sign eom failed");

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	CHECK(status == DKIM_STAT_OK, "ed25519 getsighdr failed");
	dkim_free(sign_dkim);

	vrfy_dkim = dkim_verify(lib, JOBID, NULL, &status);
	CHECK(vrfy_dkim != NULL, "ed25519 dkim_verify returned NULL");

	{
		unsigned char inhdr[MAXHEADER + 1];
		snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
		status = dkim_header(vrfy_dkim, inhdr, strlen(inhdr));
		CHECK(status == DKIM_STAT_OK, "ed25519 verify sig header failed");
	}

	feed_standard_headers(vrfy_dkim);
	for (i = 0; i < 4; i++)
	{
		status = dkim_test_dns_put(vrfy_dkim, C_IN, T_TXT, 0,
		                           (u_char *) RFC8463_ED_KEYNAME,
		                           (u_char *) RFC8463_RSA_PUBKEY);
		CHECK(status == 0, "failed to inject rsa DNS key");
	}

	status = dkim_eoh(vrfy_dkim);
	CHECK(status == DKIM_STAT_OK, "verify eoh failed");

	feed_standard_body(vrfy_dkim);
	status = dkim_eom(vrfy_dkim, NULL);
	CHECK(status != DKIM_STAT_OK, "k=rsa must not verify an ed25519 signature");

	/* Avoid freeing this handle until keytype/free bug is fixed. */
	dkim_close(lib);
	return 1;
}

/* ------------------------------------------------------------------ */
/* Test runner                                                        */
/* ------------------------------------------------------------------ */

typedef int (*test_func)(void);

struct test_entry
{
	const char *	name;
	test_func	func;
};

static struct test_entry all_tests[] =
{
	/* RFC 6376 Section 3.3 */
	{ "rfc6376_s3.3_rsa_sha256_verify_rfc8463_vector",
	  test_rfc6376_s3_3_rsa_sha256_verify_rfc8463_vector },
	{ "rfc6376_s3.3_rsa_sha256_roundtrip",
	  test_rfc6376_s3_3_rsa_sha256_roundtrip },

	/* RFC 6376 Section 3.4 */
	{ "rfc6376_s3.4_simple_simple",
	  test_rfc6376_s3_4_canon_simple_simple },
	{ "rfc6376_s3.4_simple_relaxed",
	  test_rfc6376_s3_4_canon_simple_relaxed },
	{ "rfc6376_s3.4_relaxed_simple",
	  test_rfc6376_s3_4_canon_relaxed_simple },
	{ "rfc6376_s3.4_relaxed_relaxed",
	  test_rfc6376_s3_4_canon_relaxed_relaxed },
	{ "rfc6376_s3.4.2_relaxed_hdr_ws_folding",
	  test_rfc6376_s3_4_relaxed_hdr_ws_folding },
	{ "rfc6376_s3.4.1_simple_hdr_strict",
	  test_rfc6376_s3_4_simple_hdr_ws_strict },
	{ "rfc6376_s3.4.4_relaxed_body_trailing",
	  test_rfc6376_s3_4_relaxed_body_trailing },
	{ "rfc6376_s3.4_crlf_fixing",
	  test_rfc6376_s3_4_crlf_fixing },

	/* RFC 6376 Section 3.5 */
	{ "rfc6376_s3.5_version_must_be_1",
	  test_rfc6376_s3_5_version_must_be_1 },
	{ "rfc6376_s3.5_missing_required_tags",
	  test_rfc6376_s3_5_missing_required_tags },
	{ "rfc6376_s3.5_expiration",
	  test_rfc6376_s3_5_expiration },
	{ "rfc6376_s3.5_body_length",
	  test_rfc6376_s3_5_body_length },

	/* RFC 6376 Section 3.6 */
	{ "rfc6376_s3.6.1_key_bad_version",
	  test_rfc6376_s3_6_key_bad_version },
	{ "rfc6376_s3.6.1_key_bad_type",
	  test_rfc6376_s3_6_key_bad_type },
	{ "rfc6376_s3.6.1_key_revoked",
	  test_rfc6376_s3_6_key_revoked },
	{ "rfc6376_s3.6.1_key_bad_hash",
	  test_rfc6376_s3_6_key_bad_hash },

	/* RFC 6376 Section 5.4 */
	{ "rfc6376_s5.4_from_must_be_signed",
	  test_rfc6376_s5_4_from_must_be_signed },

	/* RFC 6376 Section 6 */
	{ "rfc6376_s6_no_signature",
	  test_rfc6376_s6_no_signature },
	{ "rfc6376_s6_tampered_body",
	  test_rfc6376_s6_tampered_body },
	{ "rfc6376_s6_tampered_header",
	  test_rfc6376_s6_tampered_header },
	{ "rfc6376_s6_multiple_signatures",
	  test_rfc6376_s6_multiple_signatures },

	/* API conformance */
	{ "api_init_close",		test_api_init_close },
	{ "api_getmode",		test_api_getmode },
	{ "api_getid",			test_api_getid },
	{ "api_margin_and_partial",	test_api_margin_and_partial },
	{ "api_signer",			test_api_signer },
	{ "api_user_context",		test_api_user_context },
	{ "api_getresultstr",		test_api_getresultstr },
	{ "api_sig_geterrorstr",	test_api_sig_geterrorstr },
	{ "api_libversion",		test_api_libversion },
	{ "api_libfeature",		test_api_libfeature },
	{ "api_sig_syntax",		test_api_sig_syntax },
	{ "api_key_syntax",		test_api_key_syntax },
	{ "api_options",		test_api_options },
	{ "api_mail_parse",		test_api_mail_parse },
	{ "api_qp_decode",		test_api_qp_decode },
	{ "api_sig_accessors",		test_api_sig_accessors },
	{ "api_minbody",		test_api_minbody },
	{ "api_getsighdr_d",		test_api_getsighdr_d },
	{ "api_xtag",			test_api_xtag },
	{ "api_chunk",			test_api_chunk },
	{ "rfc8463_ed25519_verify_rfc_vector",
	  test_rfc8463_ed25519_verify_rfc_vector },
	{ "rfc8463_ed25519_roundtrip",
	  test_rfc8463_ed25519_roundtrip },
	{ "rfc8463_ed25519_wrong_keytype",
	  test_rfc8463_ed25519_wrong_keytype },

	{ NULL, NULL }
};

int
main(int argc, char **argv)
{
	int i;
	int failed = 0;

	printf("*** OpenDKIM RFC 6376 Conformance Test Suite\n");

	for (i = 0; all_tests[i].name != NULL; i++)
	{
		if (!all_tests[i].func())
		{
			fprintf(stderr, "FAILED: %s\n", all_tests[i].name);
			failed++;
		}
	}

	printf("\n=== Results: %d run, %d passed, %d failed, %d skipped ===\n",
	       tests_run, tests_passed, tests_run - tests_passed,
	       tests_skipped);

	return failed ? 1 : 0;
}
