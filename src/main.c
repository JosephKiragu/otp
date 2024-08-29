#include "../include/ft_otp.h"


void test_totp() {
	const unsigned char key [] = "12345678901234567890";
	ErrorDetails err = {ERROR_NONE, ""};

	// uint64_t counter = 1234;
	// int digits = 6;
	// char otp[9] ;// max 8 digits + null terminator

	// int result = generate_hotp(key, sizeof(key) - 1, counter, digits, otp, &err);

	// if (result == 0) {
	// 	printf("Generated HOTP: %s", otp);
	// } else {
	// 	printf("Error generating HOTP: %s\n", err.message);
	// }
	 const unsigned char new_key [] = "12345678901234567890";

	char otp[9];
	time_t test_time;

	// test case 1 : Time = 59 exppecting 03105718
	test_time = 59;
	int result = generate_totp(new_key, sizeof(new_key) - 1, 8, 30, test_time, otp, &err);
	printf("Test case 1 values to be expected are (Time: %ld, OTP: %s)\n", (long)test_time, otp);
	if (result != 0) {
		printf("Error generating TOTP case 1: %s\n", err.message);
		return ;
	}
	assert(strcmp(otp, "94287082") == 0);
	printf("Test case 1 passed (Time: %ld, OTP: %s)\n", (long)test_time, otp);

	// test case 2 : Timee = 1111111109
	test_time = 1111111109;
	result = generate_totp(key, sizeof(key) - 1, 8, 30, test_time, otp, &err);
	if (result != 0) {
		printf("Error generating totp case 2: %s\n", err.message);
		return ;
	}
	assert(strcmp(otp, "07081804") == 0);
	printf("Test case 2 paassed (Time: %ld, otp: %s)\n", (long)test_time, otp);

	// test case 3: time = 1234567890
	test_time = 1234567890;
	result = generate_totp(key, sizeof(key) - 1, 8, 30, test_time, otp, &err);
	if (result != 0) {
		printf("Error genrating totp case 3: %s", err.message);
		return ;
	}
	printf("Test case 2 to be expected (Time: %ld, otp: %s)\n", (long)test_time, otp);
	assert(strcmp(otp, "10712049") == 0);
	printf("Test case 3 passed(Time: %ld, otp: %s)\n", (long)test_time, otp);

	// test error handling:' invalid digit count
	result = generate_totp(key, sizeof(key) - 1, 9, 30, 0, otp, &err);
	assert(result != 0);
	assert(err.error_code == ERROR_INVALID_INPUT);
	printf("Error handling test passed.\n");

	// add more test cases
	printf("All totp cases passed!\n");
}

/////-----------------------------------------------------------------------------------------
/////-----------------------------------------------------------------------------------------
/////-----------------------------------------------------------------------------------------
/////-----------------------------------------------------------------------------------------
/////-----------------------------------------------------------------------------------------


void test_key_management() {
	unsigned char key[KEY_SIZE];
	unsigned char encrypted_data[256];
	size_t encrypted_data_len = sizeof(encrypted_data);
	unsigned char decrypted_key[KEY_SIZE];
	size_t decrypted_key_size;
	const char *password = "testpassword";
	size_t password_len = strlen(password);
	const char *filename = "test_key.enc";
	ErrorDetails err = {ERROR_NONE, ""};

	// test key generation
	if (generate_key(key, KEY_SIZE, &err) != 0) {
		handle_error(&err);
		return;
	}

	printf("key generated successfully\n");

	if (validate_key(key, KEY_SIZE, &err) != 0) {
		handle_error(&err);
		return;
	}
	printf("key validated successfully\n");
	printf("DEBUG: Original key: ");
	for (int i = 0; i < KEY_SIZE; i++) {
		printf("%02x", key[i]);
	}
	printf("\n");

	// test enrcyption
	if(encrypt_key(key, KEY_SIZE, password, password_len, encrypted_data, &encrypted_data_len, &err) != 0) {
		handle_error(&err);
		return;
	}
	printf("key encrypted successfully. encrypted data length %zu\n", encrypted_data_len);

	// test decryption
	if(decrypt_key(encrypted_data, encrypted_data_len, password, password_len, decrypted_key, &decrypted_key_size,  &err) != 0) {
		handle_error(&err);
		return;
	}
	printf("DEBUG: Decrypted key: ");
	for (int i = 0; i < (int)decrypted_key_size; i++) {
		printf("%02x", decrypted_key[i]);
	}
	printf("\n");
	printf("key decrypted successfully. Deccrypted key size : %zu\n", decrypted_key_size);

	assert(decrypted_key_size == KEY_SIZE);
	assert(memcmp(key, decrypted_key, KEY_SIZE) == 0);
	printf("decrypted key matches original key\n");


	// Test file I/O
	if (save_encrypted_key(filename, encrypted_data, encrypted_data_len, &err) != 0) {
		handle_error(&err);
		return;
	}
	printf("encrypted key saved to file successfully\n");

	unsigned char loaded_data[1024];
	size_t loaded_data_len = sizeof(loaded_data);
	if(load_encrypted_key(filename, loaded_data, &loaded_data_len, &err) != 0) {
		handle_error(&err);
		return;
	}

	printf("encrypted key laoded from file successfully. loaded data length: %zu\n", loaded_data_len);

	assert(memcmp(encrypted_data, loaded_data, encrypted_data_len) == 0);
	printf("loaded data matches original encrypted data.\n");


	// clean up
	remove(filename);
	printf("all key mangement tests passsed!\n");
}

int main() {
	
	test_key_management();

	return 0;


}