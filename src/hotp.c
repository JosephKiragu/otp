#include "../include/ft_otp.h"

static uint32_t dynamic_truncation(const unsigned char *hmac_result) {
	// initiaal staate:
	// -hmac result: 20-bytee HMAC-SHA1 result

	// Transformation: extract a 4-byte dynaamic array code
	uint8_t offset = hmac_result[SHA1_DIGEST_LENGTH - 1] & 0xf;
	uint32_t binary_code = (hmac_result[offset] & 0x7f) << 24 |
							(hmac_result[offset + 1] & 0xff) << 16 |
							(hmac_result[offset + 2] & 0xff) << 8 |
							(hmac_result[offset + 3] & 0xff);

	// desired state: 31 bit intager extracted from hnc result
	return binary_code;

}

int generate_hotp(const unsigned char *key, size_t key_len, uint64_t counter, int digits, char *otp, ErrorDetails *err)  {
	// intiaal state:
	// key: secret keey for hmac
	// lkey-len: length of the secret keey
	// counter: counter value
	// digiys: desired leenfth pf th eotp
	// otp : unitiaalized buffer to store the resulting otp

	// transfotmation
	//1. Validate input
	if (digits < 6 || digits > 8) {
		set_error(err, ERROR_INVALID_INPUT, "Invalid counter value");
		return -1;
	}

	unsigned char counter_bytes[8]; // four countinng otp genrated
	unsigned char *hmac_result = allocate_memory(SHA1_DIGEST_LENGTH, err); // to bee fred
	if (hmac_result == NULL) {
	}

	unsigned int hmac_len; // variable for storing length of generaated hmac
	uint32_t binary_code; // generated hmaac

	// convert counter to big endian
	for (int i = 7 ; i >= 0 ; i--) {
		counter_bytes[i] = counter & 0xff;
		counter >>= 8; 
	}

	// compute hmac
	if (!compute_hmac_sha1(key, key_len, counter_bytes, sizeof(counter_bytes), hmac_result, &hmac_len)){
		set_error(err, ERROR_HMAC_COMPUTATION_FAILED, "HMAC computaion faialed");
		goto cleanup;
	}

	// peerfoem dynamioc truncaation
	binary_code = dynamic_truncation(hmac_result);

	// generate hotp
	uint32_t hotp_value = binary_code % (uint32_t)pow(10, digits);

	// convert to string
	snprintf(otp, digits + 1, "%0*u", digits, hotp_value);


	// desried state
	// top: string containing genrated hotp
	// err: contains HOTP_ERROR_NONE if successful error code if not
	// return value: 0 for success , -1 for failure
cleanup:
	// clearing sensitive daata
	if (hmac_result != NULL) {
		OPENSSL_cleanse(hmac_result, SHA1_DIGEST_LENGTH);
		free(hmac_result);
	}
	OPENSSL_cleanse(&binary_code, sizeof(binary_code));// overwrotes with zeeross

	return (err->error_code == ERROR_NONE ? 0 : -1);


}