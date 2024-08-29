#define OPENSSL_API_COMPAT 0x10100000L

#include "../include/ft_otp.h"

int compute_hmac_sha1(const unsigned char *key, size_t key_len,
					const unsigned char *data, size_t data_len,
					unsigned char *digest, unsigned int *digest_len) {
	
	// Initial state: 
	// key : input for hmac
	// data: input data to be hashed
	// digest: uninitialized buffer for the resulting hmac
	// digest_len: Pointer to store the length of the resulting hmac
	HMAC_CTX *ctx = NULL;
	int result = 0;
	unsigned long long err_code;

	// Transformaation:
	// initialize openssl and HMAC context
	// compute HMAC-SHAA1
	// Clen up the resources

	// intilaize openssl
	OpenSSL_add_all_digests();

	// create and initialize hmac context
	ctx = HMAC_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Errro creating HMAC Context\n");
		return -1;
	}

	// initialize HMAC-SHAA1
	if(!HMAC_Init_ex(ctx, key, key_len, EVP_sha1(), NULL)){
		ERR_print_errors_fp(stderr);
		err_code = ERR_get_error();
		fprintf(stderr, "HMAC_Init failed: %s", ERR_error_string(err_code, NULL));
		goto cleanup;
	}

	// process the data
	if (!HMAC_Update(ctx, data, data_len)) {
		err_code = ERR_get_error();
		fprintf(stderr, "HMAC_update failed: %s", ERR_error_string(err_code, NULL));
		goto cleanup;
	}

	// Finalzie the HMAAC computation
	if (!HMAC_Final(ctx, digest, digest_len)) {
		err_code = ERR_get_error();
		fprintf(stderr, "HMAC_final failed: %s",ERR_error_string(err_code, NULL));
		goto cleanup;
	}

	result = 1;

cleanup:
		// clean up
	HMAC_CTX_free(ctx);

		// clear sensitive data
	OPENSSL_cleanse((void*)key, key_len);

	// desired state:
	// digest: Compputed HMAC-SHA1 digest
	// digest_len: Length of the compuuted digest
	// resuult: 1 if succesful 0 if error

	return result;


}

