/*
 * (C) Copyright 2020 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. 8F-30005.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */
#include <stdio.h>
#include <string.h>
#include <daos.h>

int
main(int argc, char **argv)
{
	int	rc;
	char option;

	/** initialize the local DAOS stack */
	rc = daos_init();
	if(rc != 0) {
		printf("daos_init failed with %d\n", rc);
		exit(-1);
	}

	printf("Enter x and hit return to terminate the process.\n");
	printf("Enter enter any key and hit return to exit cleanly.\n");

	rc = scanf("%c", &option);
	if (rc != 1 || option == 'x' || option == 'X') {
		exit(-1);
	}

	/** shutdown the local DAOS stack */
	rc = daos_fini();
	if (rc != 0) {
		printf("daos_fini failed with %d", rc);
		exit(-1);
	}

	return rc;
}
