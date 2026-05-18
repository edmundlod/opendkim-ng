/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2015, The Trusted Domain Project.  All rights reserved.
*/

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "build-config.h"

/* libopendkim includes */
#include "dkim-internal.h"
#include "dkim-types.h"
#include "dkim-keys.h"
#include "dkim-test.h"
#include "util.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* prototypes */
extern void dkim_error __P((DKIM *, const char *, ...));

/* local definitions needed for DNS queries */
#define MAXPACKET		8192
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */
#ifndef T_RRSIG
# define T_RRSIG		46
#endif /* ! T_RRSIG */

/*
**  DKIM_GET_KEY_DNS -- retrieve a DKIM key from DNS
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	buf -- buffer into which to write the result
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_get_key_dns(DKIM *dkim, DKIM_SIGINFO *sig, u_char *buf, size_t buflen)
{
	int status;
	int qdcount;
	int ancount;
	int error;
	int dnssec = DKIM_DNSSEC_UNKNOWN;
	int c;
	int n = 0;
	int rdlength = 0;
	int type = -1;
	int class = -1;
	size_t anslen;
	void *q;
	DKIM_LIB *lib;
	unsigned char *txtfound = NULL;
	unsigned char *p;
	unsigned char *cp;
	unsigned char *eom;
	unsigned char *eob;
	unsigned char qname[DKIM_MAXHOSTNAMELEN + 1];
	unsigned char ansbuf[MAXPACKET];
	struct timeval timeout;
	HEADER hdr;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(sig->sig_selector != NULL);
	assert(sig->sig_domain != NULL);

	lib = dkim->dkim_libhandle;

	n = snprintf((char *) qname, sizeof qname, "%s.%s.%s",
	             sig->sig_selector, DKIM_DNSKEYNAME, sig->sig_domain);
	if (n == -1 || (size_t) n >= sizeof qname)
	{
		dkim_error(dkim, "key query name too large");
		return DKIM_STAT_NORESOURCE;
	}

	/* see if there's a simulated reply queued; if so, use it */
	anslen = dkim_test_dns_get(dkim, ansbuf, sizeof ansbuf);
	/*
	**  dkim_test_dns_get() returns size_t but documents -1 as the "no
	**  reply queued" sentinel; that converts to SIZE_MAX, so compare
	**  against (size_t) -1 rather than a bare -1 to silence
	**  -Wsign-compare.
	*/
	if (anslen == (size_t) -1)
	{
		anslen = sizeof ansbuf;

		timeout.tv_sec = dkim->dkim_timeout;
		timeout.tv_usec = 0;

		if (lib->dkiml_dns_service == NULL &&
		    lib->dkiml_dns_init != NULL &&
		    lib->dkiml_dns_init(&lib->dkiml_dns_service) != 0)
		{
			dkim_error(dkim, "cannot initialize resolver");
			return DKIM_STAT_KEYFAIL;
		}

		status = lib->dkiml_dns_start(lib->dkiml_dns_service, T_TXT,
		                              qname, ansbuf, anslen, &q);

		if (status != 0)
		{
			dkim_error(dkim, "'%s' query failed", qname);
			return DKIM_STAT_KEYFAIL;
		}
	
		if (lib->dkiml_dns_callback == NULL)
		{
			timeout.tv_sec = dkim->dkim_timeout;
			timeout.tv_usec = 0;

			status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
			                                  q,
			                                  dkim->dkim_timeout == 0 ? NULL
			                                                          : &timeout,
			                                  &anslen, &error,
			                                  &dnssec);
		}
		else
		{
			struct timeval master;
			struct timeval next;
			struct timeval *wt;

			(void) gettimeofday(&master, NULL);
			master.tv_sec += dkim->dkim_timeout;

			for (;;)
			{
				(void) gettimeofday(&next, NULL);
				next.tv_sec += lib->dkiml_callback_int;

				dkim_min_timeval(&master, &next,
				                 &timeout, &wt);

				status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
				                                  q,
				                                  dkim->dkim_timeout == 0 ? NULL
				                                                          : &timeout,
				                                  &anslen,
				                                  &error,
				                                  &dnssec);

				if (wt == &next)
				{
					if (status == DKIM_DNS_NOREPLY ||
					    status == DKIM_DNS_EXPIRED)
						lib->dkiml_dns_callback(dkim->dkim_user_context);
					else
						break;
				}
				else
				{
					break;
				}
			}
		}

		if (status == DKIM_DNS_EXPIRED)
		{
			(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q);
			dkim_error(dkim, "'%s' query timed out", qname);
			return DKIM_STAT_KEYFAIL;
		}
		else if (status == DKIM_DNS_ERROR)
		{
			(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q);
			dkim_error(dkim, "'%s' query failed", qname);
			return DKIM_STAT_KEYFAIL;
		}

		(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q);

		sig->sig_dnssec_key = dnssec;
	}

	/* set up pointers */
	memcpy(&hdr, ansbuf, sizeof hdr);
	cp = (u_char *) &ansbuf + HFIXEDSZ;
	eom = (u_char *) &ansbuf + anslen;

	/* skip over the name at the front of the answer */
	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		if (dn_expand((unsigned char *) &ansbuf, eom, cp,
		              (char *) qname, sizeof qname) < 0)
		{
			dkim_error(dkim, "reply corrupt");
			return DKIM_STAT_KEYFAIL;
		}

		if ((n = dn_skipname(cp, eom)) < 0)
		{
			dkim_error(dkim, "'%s' reply corrupt", qname);
			return DKIM_STAT_KEYFAIL;
		}
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			dkim_error(dkim, "'%s' reply corrupt", qname);
			return DKIM_STAT_KEYFAIL;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != T_TXT || class != C_IN)
	{
		dkim_error(dkim, "'%s' unexpected reply class/type (%d/%d)",
		           qname, class, type);
		return DKIM_STAT_KEYFAIL;
	}

	/* if NXDOMAIN, return DKIM_STAT_NOKEY */
	if (hdr.rcode == NXDOMAIN)
	{
		dkim_error(dkim, "'%s' record not found", qname);
		return DKIM_STAT_NOKEY;
	}

	/* if truncated, we can't do it */
	if (dkim_check_dns_reply(ansbuf, anslen, C_IN, T_TXT) == 1)
	{
		dkim_error(dkim, "'%s' reply truncated", qname);
		return DKIM_STAT_KEYFAIL;
	}

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return DKIM_STAT_NOKEY;

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) &ansbuf, eom, cp,
		                   (RES_UNC_T) qname, sizeof qname)) < 0)
		{
			dkim_error(dkim, "'%s' reply corrupt", qname);
			return DKIM_STAT_KEYFAIL;
		}
		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ + INT32SZ + INT16SZ > eom)
		{
			dkim_error(dkim, "'%s' reply corrupt", qname);
			return DKIM_STAT_KEYFAIL;
		}

		GETSHORT(type, cp);			/* TYPE */
		GETSHORT(class, cp);			/* CLASS */
		/* skip the TTL */
		cp += INT32SZ;				/* TTL */
		GETSHORT(n, cp);			/* RDLENGTH */

		/* skip CNAME if found; assume it was resolved */
		if (type == T_CNAME)
		{
			cp += n;
			continue;
		}
		else if (type == T_RRSIG)
		{
			cp += n;
			continue;
		}
		else if (type != T_TXT)
		{
			dkim_error(dkim, "'%s' reply was unexpected type %d",
			           qname, type);
			return DKIM_STAT_KEYFAIL;
		}

		if (txtfound != NULL)
		{
			dkim_error(dkim, "multiple DNS replies for '%s'",
			           qname);
			return DKIM_STAT_MULTIDNSREPLY;
		}

		/* remember where this one started */
		txtfound = cp;
		rdlength = n;

		/* move forward for now */
		cp += n;
	}

	/* if ancount went below 0, there were no good records */
	if (txtfound == NULL)
	{
		dkim_error(dkim, "'%s' reply was unresolved CNAME", qname);
		return DKIM_STAT_NOKEY;
	}

	/* come back to the one we found */
	cp = txtfound;

	/*
	**  XXX -- maybe deal with a partial reply rather than require
	**  	   it all
	*/

	if (cp + rdlength > eom)
	{
		dkim_error(dkim, "'%s' reply corrupt", qname);
		return DKIM_STAT_SYNTAX;
	}

	/* extract the payload */
	memset(buf, '\0', buflen);
	p = buf;
	eob = buf + buflen - 1;
	while (rdlength > 0 && p < eob)
	{
		c = *cp++;
		rdlength--;
		/* clamp the per-chunk length byte against the remaining
		   rdata so a forged TXT record cannot advance cp past the
		   end of the answer buffer (an OOB read on the stack-
		   resident ansbuf, surfaced via the returned key bytes) */
		if (c > rdlength)
			c = rdlength;
		while (c > 0 && p < eob)
		{
			*p++ = *cp++;
			c--;
			rdlength--;
		}
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_GET_KEY_FILE -- retrieve a DKIM key from a text file (for testing)
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	buf -- buffer into which to write the result
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Notes:
**  	The file opened is defined by the library option DKIM_OPTS_QUERYINFO
**  	and must be set prior to use of this function.  Failing to do
**  	so will cause this function to return DKIM_STAT_KEYFAIL every time.
**  	The file should contain lines of the form:
** 
**  		<selector>._domainkey.<domain> <space> key-data
**
**  	Case matching on the left is case-sensitive, but libopendkim already
**  	wraps the domain name to lowercase.
*/

DKIM_STAT
dkim_get_key_file(DKIM *dkim, DKIM_SIGINFO *sig, u_char *buf, size_t buflen)
{
	int n;
	FILE *f;
	u_char *p;
	u_char *p2;
	u_char *path;
	char name[DKIM_MAXHOSTNAMELEN + 1];

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(sig->sig_selector != NULL);
	assert(sig->sig_domain != NULL);
	assert(sig->sig_query == DKIM_QUERY_FILE);

	path = dkim->dkim_libhandle->dkiml_queryinfo;
	if (path[0] == '\0')
	{
		dkim_error(dkim, "query file not defined");
		return DKIM_STAT_KEYFAIL;
	}

	f = fopen((char *) path, "r");
	if (f == NULL)
	{
		dkim_error(dkim, "%s: fopen(): %s", path, strerror(errno));
		return DKIM_STAT_KEYFAIL;
	}

	n = snprintf(name, sizeof name, "%s.%s.%s", sig->sig_selector,
	             DKIM_DNSKEYNAME, sig->sig_domain);
	if (n == -1 || (size_t) n >= sizeof name)
	{
		dkim_error(dkim, "key query name too large");
		fclose(f);
		return DKIM_STAT_NORESOURCE;
	}

	memset(buf, '\0', buflen);
	while (fgets((char *) buf, buflen, f) != NULL)
	{
		if (buf[0] == '#')
			continue;

		p2 = NULL;

		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\n')
			{
				*p = '\0';
				break;
			}
			else if (isascii(*p) && isspace(*p))
			{
				*p = '\0';
				p2 = p + 1;
			}
			else if (p2 != NULL)
			{
				break;
			}
		}

		if (strcasecmp((char *) name, (char *) buf) == 0 && p2 != NULL)
		{
			memmove(buf, p2, strlen(p2) + 1);
			fclose(f);
			return DKIM_STAT_OK;
		}
	}

	fclose(f);

	return DKIM_STAT_NOKEY;
}
