#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include "gradm.h"

#define PAM_SERVICENAME "gradm"

int gradm_pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	int i, x;
	struct pam_response *response;
	char *p;

	/* arbitrary OpenSSH-style limiting */
	if (num_msg <= 0 || num_msg > 1000)
		return PAM_CONV_ERR;

	response = malloc(num_msg * sizeof(struct pam_response));
	if (response == NULL)
		return PAM_CONV_ERR;
	for (i = 0; i < num_msg; i++) {
		response[i].resp_retcode = 0;
		response[i].resp = NULL;
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			fputs(msg[i]->msg, stdout);
			response[i].resp = calloc(1, PAM_MAX_RESP_SIZE);
			if (response[i].resp == NULL)
				failure("calloc");
			p = NULL;
			while (p == NULL)
				p = fgets(response[i].resp, PAM_MAX_RESP_SIZE, stdin);
			while (*p) {
				if (*p == '\n')
					*p = '\0';
				else
					p++;
			}
			break;
		case PAM_PROMPT_ECHO_OFF:
			p = getpass(msg[i]->msg);
			if (p == NULL)
				failure("getpass");
			response[i].resp = strdup(p);
			/* zero out static buffer */
			memset(p, 0, strlen(p));
			if (response[i].resp == NULL)
				failure("strdup");
			break;
		case PAM_ERROR_MSG:
			fputs(msg[i]->msg, stderr);
			break;
		case PAM_TEXT_INFO:
			fputs(msg[i]->msg, stdout);
			break;
		default:
			for (x = i; x >= 0; x--) {
				if (response[x].resp != NULL) {
					memset(response[x].resp, 0, strlen(response[x].resp));
					free(response[x].resp);
					response[x].resp = NULL;
				}
			}
			free(response);
			return PAM_CONV_ERR;
		}
	}

	*resp = response;

	return PAM_SUCCESS;
}

int main(int argc, char *argv[])
{
	pam_handle_t *pamh = NULL;
	int retval;
	struct pam_conv conv = { gradm_pam_conv, NULL };
	struct gr_arg_wrapper wrapper;
	struct gr_arg arg;
	int fd;

	if (argc != 2)
		exit(EXIT_FAILURE);

	wrapper.version = GRADM_VERSION;
	wrapper.size = sizeof(struct gr_arg);
	wrapper.arg = &arg;
	arg.mode = GRADM_STATUS;

	if ((fd = open(GRDEV_PATH, O_WRONLY)) < 0) {
		fprintf(stderr, "Could not open %s.\n", GRDEV_PATH);
		failure("open");
	}

	retval = write(fd, &wrapper, sizeof(struct gr_arg_wrapper));
	close(fd);

	if (retval != 1)
		exit(EXIT_FAILURE);
	
	retval = pam_start(PAM_SERVICENAME, argv[1], &conv, &pamh);

	if (retval == PAM_SUCCESS)
		retval = pam_authenticate(pamh, 0);

	if (retval == PAM_SUCCESS)
		retval = pam_acct_mgmt(pamh, 0);

	if (retval == PAM_AUTHTOK_EXPIRED)
		retval = pam_chauthtok(pamh, 0);

	if (pamh)
		pam_end(pamh, retval);

	if (retval != PAM_SUCCESS)
		exit(EXIT_FAILURE);

	return EXIT_SUCCESS;
}
