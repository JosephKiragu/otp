#include "../include/ft_otp.h"

#define PBKDF2_ITERATIONS 10000


static const unsigned char MAGIC_BYTES[] = {0xDE, 0xAD, 0xBE, 0xEF};

int generate_key(unsigned char *key, size_t key_size, ErrorDetails *err) {
	// initiala state:
	// key : unitinitalized key buffer for storing scret key for hmac generation
	// key_size : desired length of the key

	// transformation: Generaate crytpograpahically secure raandoom bytes
	if (RAND_bytes(key, key_size) != 1) {
		unsigned long openssl_error = ERR_get_error();
		char error_string[256];
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_RANDOM_GENERATION, error_string);
		return -1;
	}

	// final state: key buffer filled with random bytes
	return 0;

}

static double calculate_shannon_entropy(const unsigned char *data, size_t data_size, ErrorDetails *err) {
	// initial state: validate input
	if (data == NULL || data_size == 0) {
		set_error(err, ERROR_INVALID_INPUT, "either hash pointer or hash size wrong in calculate shannon");
		return -1.0;
	}
	// data: hash to calculate entropy
	// data_size: size of the hash
	int frequency[256] = {0}; // buffer for storing input
	double entropy = 0.0;

	// transformation state: popuulate frequency with hash
	for (size_t i = 0; i < data_size; i++) {
		frequency[data[i]]++;
	}

	// calculate entropy
	for (int i = 0; i < 256; i++) {
		if(frequency[i] > 0) {
			double p = (double)frequency[i] / data_size;
			entropy -= p * log2(p);
		}
	}
	return entropy;

}

int validate_key(const unsigned char *key, size_t key_size, ErrorDetails *err) {
	// intial state: key to be validated
	// check input
	if (key == NULL || key_size == 0 || err == NULL) {
		set_error(err, ERROR_INVALID_INPUT, "invalid arguments for validate key");
	}
		

	// tranasfoormation: check key size
	if (key_size != KEY_SIZE) {
		set_error(err, ERROR_INVALID_KEY_SIZE, "Invalid key size");
		return -1;
	}

	// Simplee zero byte check
	int zero_bytes = 0;
	for (size_t i = 0; i < key_size; i++) {
		if (key[i] == 0) {
			zero_bytes++;
		}
	}

	// check foor zeros
	if (zero_bytes > (int)(key_size/4)) {
		set_error(err, ERROR_LOW_KEY_ENTROPY, "Key has more than 25% zero bytes");
		return -1;
	}

	// shannon eentropy check
	double entropy = calculate_shannon_entropy(key, key_size, err);
	if (err->error_code != ERROR_NONE) {
		printf("shannon entropy failed");
	}
	double max_entropy = log2(256);
	double entropy_ratio = entropy / max_entropy;
	printf("\nencryption entropy is : %.2f\n\n", entropy_ratio);

	// check if entroppy is too low 
	if (entropy_ratio < 0.50) { // less than 75% of maximum entropy. FIND OUT WHY 75 FAILED. HOW TO INCREASE ENTROPY	
		set_error(err, ERROR_LOW_KEY_ENTROPY, "Key has low shannoon entropy");
		return -1;
	}

	// final state: valaidaation resuult (0 fo\r valid -1 for invalid)

	return 0;
}

int encrypt_key(const unsigned char *key, size_t key_size, const char *password, size_t password_len,
				unsigned char *encrypted_data, size_t *encrypted_data_len, ErrorDetails *err) {
	// initial state: plaintext key and password
	// key: plaintext to be encrypted
	// key_size: size oof the plaintext key
	// passwoord: password for deriving the encryptiono key
	// password len: length of the passsword
	// encrypted_data : buffer for storing the encrypted key data
	// encrypted_dataa_len : pointer to stor the length of the encrypted password

	// transformation: Derive encryption key and encrypt the key
	EVP_CIPHER_CTX *ctx; // initialize openssl context for encryption // to be cleaned
	unsigned char salt[SALT_SIZE]; // buffer for storing random value
	unsigned char iv[IV_SIZE]; // buffer for storing raandom value to increase randomness
	unsigned char key_derived[32];// buffer foor storing the encryptd key
	int len, final_len;

	// calculate required buffer size
	size_t required_size = sizeof(MAGIC_BYTES) + SALT_SIZE + IV_SIZE + key_size + EVP_MAX_BLOCK_LENGTH + HMAC_SIZE;

	printf("DEBUG: initial buffer size: %zu\n", *encrypted_data_len);
	printf("DEBUG: required size: %zu\n", required_size);
	// check if provided buffer is lrge enough
	if (*encrypted_data_len < required_size) {
		set_error(err, ERROR_BUFFER_TOO_SMALL, "encryptted data buffer is small");
		return -1;
	}

	// generate salt and IV
	if (RAND_bytes(salt, SALT_SIZE) != 1 || RAND_bytes(iv, IV_SIZE) != 1) {
		unsigned long openssl_error = ERR_get_error();
		char error_string [256];
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_RANDOM_GENERATION, error_string);
		return -1;
	}
	////
	printf("\nDEBUG: salt: ");
	for(int i = 0; i < SALT_SIZE; i++) printf("%02x", salt[i]);
	printf("\nDEBUG: IV: ");
	for(int i = 0; i < IV_SIZE; i++) printf("%02x", iv[i]);
	printf("\n");
	////

	// Deriv key from password
	if (PKCS5_PBKDF2_HMAC(password, password_len, salt, SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(), 32, key_derived) != 1) {
		unsigned long openssl_error = ERR_get_error();
		char error_string[256];
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_KEY_DERIVATION, error_string);
		return -1;
	}


	////
	printf("DEBUG: Derived key: ");
	for(int i = 0; i < 32; i++) printf("%02x", key_derived[i]);
	printf("\n");
	////

	ctx = EVP_CIPHER_CTX_new(); // to b freed
	if (!ctx) {
		set_error(err, ERROR_KEY_DERIVATION, "Failed to create cipher context");
		return -1;
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_derived, iv) != 1) {
		printf("DEBUG: Cipher: %s\n", EVP_CIPHER_name(EVP_aes_256_cbc()));
		unsigned long openssl_error = ERR_get_error();
		char error_string[256];
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_ENCRYPT_ERROR, error_string);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	*encrypted_data_len = 0;
	memcpy(encrypted_data, MAGIC_BYTES, sizeof(MAGIC_BYTES));
	*encrypted_data_len += sizeof(MAGIC_BYTES);
	memcpy(encrypted_data + *encrypted_data_len, salt, SALT_SIZE);
	*encrypted_data_len += SALT_SIZE;
	memcpy(encrypted_data + *encrypted_data_len, iv, IV_SIZE);
	*encrypted_data_len += IV_SIZE;

	if (EVP_EncryptUpdate(ctx, encrypted_data + *encrypted_data_len, &len, key, key_size) != 1) {
		unsigned long openssl_error = ERR_get_error();
		char error_string[256];
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_ENCRYPT_ERROR, error_string);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	*encrypted_data_len += len;

	if (EVP_EncryptFinal_ex(ctx, encrypted_data + *encrypted_data_len, &final_len) != 1) {
		unsigned long openssl_error = ERR_get_error();
		char error_string[256];
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_ENCRYPT_ERROR, error_string);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	*encrypted_data_len += final_len;


	// calculate HMAC of the encryppted data
	printf("DEBUG: size after encryption: %zu\n", *encrypted_data_len);
	unsigned char hmac[HMAC_SIZE];
	unsigned int hmac_len;
	HMAC(EVP_sha256(), key_derived, 32, encrypted_data, *encrypted_data_len, hmac, &hmac_len);

	// ensure there is enough space for the HMAC
	if (*encrypted_data_len + HMAC_SIZE > required_size) {
		set_error(err, ERROR_BUFFER_OVERFLOW, "buffer overflow before appending hmac to encrypted data");
		return -1;
	}

	// append HMAC to the encrypted data
	memcpy(encrypted_data + *encrypted_data_len, hmac, HMAC_SIZE);
	*encrypted_data_len += HMAC_SIZE;
	printf("DEBUG: final encrypted size with HMAC: %zu\n", *encrypted_data_len);


	// finl state: Encrypted key data
	EVP_CIPHER_CTX_free(ctx);


	return 0;

}

int decrypt_key(const unsigned char *encrypted_data, size_t encrypted_data_len, 
				const char *password, size_t password_len, unsigned char *key,
				size_t *key_size, ErrorDetails *err) {

	// encrypted_data : key that was encrypted
	// encrypted_data_len : length of the encrypted key
	// password: password for deriving the key
	// password_len: length of the password
	// key : buffer for storing the key
	// key_size: pointer to length of the key
	// error_details: pointer to sstore error details of the function
	// initial state: Encrypted key and password

	// transformation: Derive encryption key and decrypt the key
	EVP_CIPHER_CTX *ctx; // open ssl context for encryption 
	unsigned char salt[SALT_SIZE]; // buffer for storing deried salt // to be null terminated
	unsigned char iv[IV_SIZE]; // buffer for storing derived iv // to be null termiinated
	unsigned char key_derived[32]; // buffer for storing the derived key
	int len, final_len;

	// check if the encrypted data is large enough to contain all necessary component
	if (encrypted_data_len < sizeof(MAGIC_BYTES) + sizeof(SALT_SIZE) + sizeof(IV_SIZE)) {
		set_error(err,ERROR_INVALID_DATA_SIZE, "encrypted data is too short");
		return -1;
	}

	// Verify the magic bytes
	if ( memcmp(encrypted_data, MAGIC_BYTES, sizeof(MAGIC_BYTES)) != 0 ) {
		set_error(err, ERROR_INVALID_MAGIC_BYTES, "Invalid magiic bytes");
		return -1;
	}

	// Extract the salt and iv
	memcpy(salt, encrypted_data + sizeof(MAGIC_BYTES), SALT_SIZE);
	memcpy(iv, encrypted_data + sizeof(MAGIC_BYTES) + SALT_SIZE, IV_SIZE);

	////
	printf("DEBUG: Extracted Salt: ");
	for(int i = 0; i < SALT_SIZE; i++) printf("%02x",salt[i]);
	printf("\nDEBUG: Extracted IV: ");
	for(int i = 0; i < IV_SIZE; i++) printf("%02x", iv[i]);
	printf("\n");
	////

	// derive key froom password
	if (PKCS5_PBKDF2_HMAC(password, password_len, salt, SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(), 32, key_derived) != 1) {
		unsigned long openssl_error = ERR_get_error();
		char error_string[256]; // buffer fort storing open ssl error
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_KEY_DERIVATION, error_string);
		return -1;
	}

	////
	printf("DEBUG: derived key: ");
	for(int i = 0; i < 32; i++) printf("%02x", key_derived[i]);
	printf("\n");
	////

	// creaate and initialize the decryption context
	ctx = EVP_CIPHER_CTX_new(); // remember to free
	if (!ctx) {
		set_error(err, ERROR_CIPHER_CONTEXT, "cipher context failed to initialize in decrypt key");
		return -1;
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_derived, iv) != 1) {
		printf("DEBUG: Cipher: %s\n", EVP_CIPHER_name(EVP_aes_256_cbc()));
		unsigned long openssl_error = ERR_get_error();
		char error_string[256];
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_DECRYPT_INIT, error_string);
		printf("error inside EVP_DecryptInit_ex \n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if (encrypted_data_len - sizeof(MAGIC_BYTES) - SALT_SIZE - IV_SIZE > INT_MAX) {
		set_error(err, ERROR_BUFFER_OVERFLOW, "encrypted data too large");
		return -1;
	}



	// verifying hmacc before decryption
	if (encrypted_data_len < HMAC_SIZE) {
		set_error(err, ERROR_INVALID_DATA_SIZE, "encrypted data too short");
		return -1;
	}
	unsigned char calculated_hmac[HMAC_SIZE];
	unsigned int hmac_len;
	HMAC(EVP_sha256(), key_derived, 32, encrypted_data, encrypted_data_len - HMAC_SIZE, calculated_hmac, &hmac_len);

	if(memcmp(calculated_hmac, encrypted_data + encrypted_data_len - HMAC_SIZE, HMAC_SIZE) != 0) {
		set_error(err, ERROR_INTEGRITY_CHECK, "HMAC verification failed");
		return -1;
	}
	printf("DEBUG: hmac verified successfully\n");

	encrypted_data_len -= HMAC_SIZE;

	// decrypt the data
	if (EVP_DecryptUpdate(ctx, key, &len, encrypted_data + sizeof(MAGIC_BYTES) + SALT_SIZE + IV_SIZE, encrypted_data_len - sizeof(MAGIC_BYTES) - SALT_SIZE - IV_SIZE) != 1) {
		unsigned long openssl_error = ERR_get_error();
		char error_string[256];
		ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
		set_error(err, ERROR_DECRYPT_UPDATE, "failed to decrypt data");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	*key_size = len;

	// finalize the decryptioon
	if (EVP_DecryptFinal_ex(ctx, key + len, &final_len) != 1) {
		
		unsigned long openssel_error = ERR_get_error();
		char error_string[256];
		ERR_error_string_n(openssel_error, error_string, sizeof(error_string));
		set_error(err, ERROR_DECRYPT_FINAL, error_string);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	*key_size += final_len;

	// final state: decrypted key
	EVP_CIPHER_CTX_free(ctx);
	return 0;

}

int save_encrypted_key(const char *filename, const unsigned char *encrypted_data,
			size_t encrypted_dat_len, ErrorDetails *err) {
	
	// initial tate: filename and encrypted_data_key

	// transformatioon: write encrypted data to file securey
	int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC , KEY_FILE_MODE);
	if (fd == -1) {
		set_error(err, ERROR_FILE_OPEN, strerror(errno));
		return -1;
	}
	// write
	ssize_t bytes_written = write(fd, encrypted_data, (ssize_t)encrypted_dat_len);
	if (bytes_written != (ssize_t)encrypted_dat_len) {
		set_error(err, ERROR_FILE_WRITE, strerror(errno));
		close(fd);
		return -1;
	}

	if (fsync(fd) == -1) {
		set_error(err, ERROR_FILE_SYNC, "error syncing file");
		close(fd);
		return -1;
	}

	// final state: ecnrypted key saved to file
	close(fd);
	return 0;
}

int load_encrypted_key(const char *filename, unsigned char *encrypted_data, size_t *encrypted_data_len, ErrorDetails *err) {
	// initial state: filename nd buffer for encrypted data

	// transformation: read encrypted data from file ecurely
	int fd = open(filename, O_RDONLY);
	if (fd == -1) {
		set_error(err, ERROR_FILE_OPEN, "error opening file");
		return -1;
	}

	struct stat st;
	if (fstat(fd, &st) == -1) {
		set_error(err, ERROR_FILE_STAT, strerror(errno));
		close(fd);
		return -1;
	}

	if ((size_t)st.st_size > *encrypted_data_len) {
		set_error(err, ERROR_BUFFER_TOO_SMALL, "provided buffer is too small for content");
		return -1;
	}

	ssize_t bytes_read = read(fd, encrypted_data, st.st_size);
	if (bytes_read != st.st_size) {
		set_error(err, ERROR_FILE_READ, strerror(errno));
		close(fd);
		return -1;
	}

	*encrypted_data_len = bytes_read;

	// finl: encrypted key laoded from file
	close(fd);
	return 0;




}