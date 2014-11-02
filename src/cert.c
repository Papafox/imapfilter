#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "imapfilter.h"
#include "session.h"


extern environment env;


int check_cert(X509 *pcert, unsigned char *pmd, unsigned int *pmdlen);
void print_cert(X509 *cert, unsigned char *md, unsigned int *mdlen);
char *get_serial(X509 *cert);
int write_cert(X509 *cert);
int mismatch_cert(void);
char *getVerifyMessage(long code);


/*
 * Get SSL/TLS certificate check it, maybe ask user about it and act
 * accordingly.
 * 
 * Modified to use OpenSSL to verify the certificate.  If OpenSSL thinks the
 * certificate is valid, then accept it.  Otherwise if the Certicate is self
 * signed or the certifcate issuer cannot be verified (probably because there
 * is no truststore) then validate it against the ~/.imapfilter/certicates file.
 */
int
get_cert(session *ssn)
{
	X509 *cert;
	int cert_flag;
	long verify;
	const char *verify_text;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen;

	mdlen = 0;
	cert_flag = get_option_boolean("certificates");

	if (!(cert = SSL_get_peer_certificate(ssn->sslconn)))
		return -1;

	/*	If certificate validated normally, accept it	*/
	verify = SSL_get_verify_result(ssn->sslconn);
	verify_text = getVerifyMessage(verify);
	verbose("SSL: Certificate subject = %s\n", X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
	verbose("SSL: Certicate verify result = (%d) %s\n", verify, verify_text);
	if (verify == X509_V_OK)
	    return 0;
	
	/*	
	 * 	Reject malformed certificates with an error.  Only allow certificates which
	 *	either have an issuer which was not found in the truststore (or there is no truststore)
	 * 	or is self signed.  For either of these cases, verify the certificate using the
	 * 	'~/.imapfilter/certificates' file.
	 * 
	 * 	if options.certificates is false, then any validation error (including self signed and
	 * 	unknown issuer is fatal.
	 */
	int cert_error = 1;
	if (cert_flag)
	{
	    if (verify == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
		cert_error = 0;
	    if (verify == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
		cert_error = 0;
	}
	if (cert_error)
	{
	    fatal(ERROR_CERTIFICATE, "Certificate validation error: (%d) %s\n", verify, verify_text);
	    return -1;
	}

	/* Check is certificates file is disallowed	*/
	if (!cert_flag)
	    goto fail;
	
	/* Verbose warning	*/
	char *certf = get_filepath("certificates");
	verbose("SSL: Certicate will be verified using file '%s'\n", certf);
	xfree(certf);
	
	/*	Process a self-signed certificate using the "certificates" file		*/
	if (!(X509_digest(cert, EVP_md5(), md, &mdlen)))
		return -1;

	switch (check_cert(cert, md, &mdlen)) {
	case 0:
		if (isatty(STDIN_FILENO) == 0)
			fatal(ERROR_CERTIFICATE, "%s\n",
			    "can't accept certificate in non-interactive mode");
		print_cert(cert, md, &mdlen);
		if (write_cert(cert) == -1)
			goto fail;
		break;
	case -1:
		if (isatty(STDIN_FILENO) == 0)
			fatal(ERROR_CERTIFICATE, "%s\n",
			    "certificate mismatch in non-interactive mode");
		print_cert(cert, md, &mdlen);
		if (mismatch_cert() == -1)
			goto fail;
		break;
	}

	X509_free(cert);

	return 0;

fail:
	X509_free(cert);

	return -1;
}


/*
 * Check if the SSL/TLS certificate exists in the certificates file.
 */
int
check_cert(X509 *pcert, unsigned char *pmd, unsigned int *pmdlen)
{
	int r;
	FILE *fd;
	char *certf;
	X509 *cert;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen;

	r = 0;
	cert = NULL;

	certf = get_filepath("certificates");
	if (!exists_file(certf)) {
		xfree(certf);
		return 0;
	}
	fd = fopen(certf, "r");
	xfree(certf);
	if (fd == NULL)
		return -1;

	while ((cert = PEM_read_X509(fd, &cert, NULL, NULL)) != NULL) {
		if (X509_subject_name_cmp(cert, pcert) != 0 ||
		    X509_issuer_and_serial_cmp(cert, pcert) != 0)
			continue;

		if (!X509_digest(cert, EVP_md5(), md, &mdlen) ||
		    *pmdlen != mdlen)
			continue;

		if (memcmp(pmd, md, mdlen) != 0) {
			r = -1;
			break;
		}
		r = 1;
		break;
	}

	fclose(fd);
	X509_free(cert);

	return r;
}


/*
 * Print information about the SSL/TLS certificate.
 */
void
print_cert(X509 *cert, unsigned char *md, unsigned int *mdlen)
{
	unsigned int i;
	char *s;

	s = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	printf("Server certificate subject: %s\n", s);
	xfree(s);

	s = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	printf("Server certificate issuer: %s\n", s);
	xfree(s);

	s = get_serial(cert);
	printf("Server certificate serial: %s\n", s);
	xfree(s);

	printf("Server key fingerprint: ");
	for (i = 0; i < *mdlen; i++)
		printf(i != *mdlen - 1 ? "%02X:" : "%02X\n", md[i]);
}


/*
 * Extract certificate serial number as a string.
 */
char *
get_serial(X509 *cert)
{
	ASN1_INTEGER* serial;
	char *buf;
	long num;
	int  i;
	size_t len;

	serial = X509_get_serialNumber(cert);
	buf = xmalloc(LINE_MAX);
	*buf = '\0';
	if (serial->length <= (int)sizeof(long)) {
		num = ASN1_INTEGER_get(serial);
		if (serial->type == V_ASN1_NEG_INTEGER) {
			snprintf(buf, LINE_MAX, "-%lX", -num);
		} else {
			snprintf(buf, LINE_MAX, "%lX", num);
		}
	} else {
		if (serial->type == V_ASN1_NEG_INTEGER) {
			snprintf(buf, LINE_MAX, "-");
		}
		for (i = 0; i < serial->length; i++) {
			len = strlen(buf);
			snprintf(buf + len, LINE_MAX - len, "%02X",
			    serial->data[i]);
		}
	}
	return buf;
}


/*
 * Write the SSL/TLS certificate after asking the user to accept/reject it.
 */
int
write_cert(X509 *cert)
{
	FILE *fd;
	char c, buf[LINE_MAX];
	char *certf;
	char *s;

	do {
		printf("(R)eject, accept (t)emporarily or "
		    "accept (p)ermanently? ");
		if (fgets(buf, LINE_MAX, stdin) == NULL)
			return -1;
		c = tolower((int)(*buf));
	} while (c != 'r' && c != 't' && c != 'p');

	if (c == 'r')
		return -1;
	else if (c == 't')
		return 0;

	certf = get_filepath("certificates");
	create_file(certf, S_IRUSR | S_IWUSR);
	fd = fopen(certf, "a");
	xfree(certf);
	if (fd == NULL)
		return -1;

	s = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	fprintf(fd, "Subject: %s\n", s);
	xfree(s);
	s = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	fprintf(fd, "Issuer: %s\n", s);
	xfree(s);
	s = get_serial(cert);
	fprintf(fd, "Serial: %s\n", s);
	xfree(s);

	PEM_write_X509(fd, cert);

	fprintf(fd, "\n");
	fclose(fd);

	return 0;
}


/*
 * Ask user to proceed, while a fingerprint mismatch in the SSL/TLS certificate
 * was found.
 */
int
mismatch_cert(void)
{
	char c, buf[LINE_MAX];

	do {
		printf("ATTENTION: SSL/TLS certificate fingerprint mismatch.\n"
		    "Proceed with the connection (y/n)? ");
		if (fgets(buf, LINE_MAX, stdin) == NULL)
			return -1;
		c = tolower((int)(*buf));
	} while (c != 'y' && c != 'n');

	if (c == 'y')
		return 0;
	else
		return -1;
}

/*
 * 	Translate an OpenSSL verify error code to text
 */
char *
getVerifyMessage(long code)
{
    static const struct _ErrorTab
    {
	char	text[64];
	long	code;
    } errorTab[] =
	{
		{	"OK",						0	},
		{	"ERR_UNABLE_TO_GET_ISSUER_CERT",		2	},
		{	"ERR_UNABLE_TO_GET_CRL",			3	},
		{	"ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE",		4	},
		{	"ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE",		5	},
		{	"ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",	6	},
		{	"ERR_CERT_SIGNATURE_FAILURE",			7	},
		{	"ERR_CRL_SIGNATURE_FAILURE",			8	},
		{	"ERR_CERT_NOT_YET_VALID",			9	},
		{	"ERR_CERT_HAS_EXPIRED",				10	},
		{	"ERR_CRL_NOT_YET_VALID",			11	},
		{	"ERR_CRL_HAS_EXPIRED",				12	},
		{	"ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD",		13	},
		{	"ERR_ERROR_IN_CERT_NOT_AFTER_FIELD",		14	},
		{	"ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD",		15	},
		{	"ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD",		16	},
		{	"ERR_OUT_OF_MEM",				17	},
		{	"ERR_DEPTH_ZERO_SELF_SIGNED_CERT",		18	},
		{	"ERR_SELF_SIGNED_CERT_IN_CHAIN",		19	},
		{	"ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",	20	},
		{	"ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE",		21	},
		{	"ERR_CERT_CHAIN_TOO_LONG",			22	},
		{	"ERR_CERT_REVOKED",				23	},
		{	"ERR_INVALID_CA",				24	},
		{	"ERR_PATH_LENGTH_EXCEEDED",			25	},
		{	"ERR_INVALID_PURPOSE",				26	},
		{	"ERR_CERT_UNTRUSTED",				27	},
		{	"ERR_CERT_REJECTED",				28	},
		{	"ERR_SUBJECT_ISSUER_MISMATCH",			29	},
		{	"ERR_AKID_SKID_MISMATCH",			30	},
		{	"ERR_AKID_ISSUER_SERIAL_MISMATCH",		31	},
		{	"ERR_KEYUSAGE_NO_CERTSIGN",			32	},
		{	"ERR_UNABLE_TO_GET_CRL_ISSUER",			33	},
		{	"ERR_UNHANDLED_CRITICAL_EXTENSION",		34	},
		{	"ERR_KEYUSAGE_NO_CRL_SIGN",			35	},
		{	"ERR_UNHANDLED_CRITICAL_CRL_EXTENSION",		36	},
		{	"ERR_INVALID_NON_CA",				37	},
		{	"ERR_PROXY_PATH_LENGTH_EXCEEDED",		38	},
		{	"ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE",		39	},
		{	"ERR_PROXY_CERTIFICATES_NOT_ALLOWED",		40	},
		{	"ERR_INVALID_EXTENSION",			41	},
		{	"ERR_INVALID_POLICY_EXTENSION",			42	},
		{	"ERR_NO_EXPLICIT_POLICY",			43	},
		{	"ERR_DIFFERENT_CRL_SCOPE",			44	},
		{	"ERR_UNSUPPORTED_EXTENSION_FEATURE",		45	},
		{	"ERR_UNNESTED_RESOURCE",			46	},
		{	"ERR_PERMITTED_VIOLATION",			47	},
		{	"ERR_EXCLUDED_VIOLATION",			48	},
		{	"ERR_SUBTREE_MINMAX",				49	},
		{	"ERR_APPLICATION_VERIFICATION",			50	},
		{	"ERR_UNSUPPORTED_CONSTRAINT_TYPE",		51	},
		{	"ERR_UNSUPPORTED_CONSTRAINT_SYNTAX",		52	},
		{	"ERR_UNSUPPORTED_NAME_SYNTAX",			53	},
		{	"ERR_CRL_PATH_VALIDATION_ERROR",		54	}
	};
	
	int i;
	int size = sizeof(errorTab) / sizeof(errorTab[0]);
	char *result = "";
	
	for(i = 0; i < size; i++)
	{
	    if (errorTab[i].code == code)
	    {
		result = (char *)errorTab[i].text;
		break;
	    }
	}
	
	return result;
}