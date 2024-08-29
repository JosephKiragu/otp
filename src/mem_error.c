#include "../include/ft_otp.h"

void set_error(ErrorDetails *err, ErrorCode code, const char *message) {
	// initial state
	// err: pointeer to error details codee
	// code : error code to set
	// message: error message to seet

	// traansformation: set the error
	if (err != NULL && message != NULL) {
		err->error_code = code;
		snprintf(err->message, sizeof(err->message), "%s", message);
	}
	if (err->error_code != ERROR_NONE) {
		printf("Error with : %s", err->message);
	}
	// desired stat: err conrains error message
} 


void* allocate_memory(size_t size, ErrorDetails *err) {
	// initial: desired allocation, unitialized err

	// transformation: allocate memory
	void *ptr = malloc(size);

	// desried atet:
	// memory allocated or error occured
	if (ptr == NULL) {
		set_error(err, ERROR_MEMORY_ALLOCATION, "memory allocation failed");
		return NULL;
	}

	return ptr;
	
}

void handle_error(ErrorDetails *err) {
	if (err != NULL && err->error_code != ERROR_NONE) {
		fprintf(stderr, "Error : %s", err->message);
		exit(EXIT_FAILURE);
	}
}