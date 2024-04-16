/* Copyright 2021 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <stdbool.h>

#include "dtree.h"
#include "dtree_cronus.h"

struct cronus_export_state {
	FILE *fp;
	char *target;
	bool printed;
};

static int cronus_export_node(struct dtm_node *root, struct dtm_node *node, void *priv)
{
	struct cronus_export_state *state = (struct cronus_export_state *)priv;

	if (state->target)
		free(state->target);

	state->target = dtree_to_cronus_target(root, node);
	state->printed = false;
	return 0;
}

static int cronus_export_attr(const struct dtree_attr *attr, void *priv)
{
	struct cronus_export_state *state = (struct cronus_export_state *)priv;

	if (!state->target) {
		return 0;
	} else if (!state->printed) {
		dtree_cronus_print_node(state->target, state->fp);
		state->printed = true;
	}

	dtree_cronus_print_attr(attr, state->fp);
	return 0;
}

int dtree_cronus_export(const char *dtb_path,
			const char *infodb_path,
			const char *attrdb_path,
			FILE *fp)
{
	struct cronus_export_state state;

	state = (struct cronus_export_state) {
		.fp = fp,
	};

	return dtree_export(dtb_path, infodb_path, attrdb_path,
			    cronus_export_node, cronus_export_attr,
			    &state);
}

struct cronus_import_state {
	FILE *fp;
};

int cronus_import_parse(void *ctx, void *priv)
{
	fprintf(stderr, "swetha: inside cronus_import_parse\n");
	struct cronus_import_state *state = (struct cronus_import_state *)priv;
	char *buf;
	size_t len;
	ssize_t n;
	int ret = 0;

	len = 1024;
	buf = malloc(len);
	assert(buf);

	while((n = getline(&buf, &len, state->fp)) != -1) {
		if (buf[n-1] == '\n')
			buf[n-1] = '\0';

		ret = dtree_cronus_parse(ctx, buf);
		if (ret)
			break;
	}

	free(buf);
	return ret;
}

int dtree_cronus_import(const char *dtb_path,
			const char *infodb_path,
			FILE *fp)
{
	struct cronus_import_state state;

	state = (struct cronus_import_state) {
		.fp = fp,
	};
    fprintf(stderr, "swetha: inside dtree_cronus_import\n");
	return dtree_import(dtb_path, infodb_path, cronus_import_parse, &state);
}

