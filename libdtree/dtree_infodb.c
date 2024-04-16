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
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "dtree.h"
#include "dtree_attr.h"
#include "dtree_infodb.h"

static char *dtree_infodb_read_value(FILE *fp, char *keystr)
{
	char *line = NULL, *tok, *value;
	size_t len = 0;
	ssize_t n;

	n = getline(&line, &len, fp);
	if (n == -1)
		return NULL;

	tok = strtok(line, " ");
	if (strcmp(tok, keystr)) {
		free(line);
		return NULL;
	}

	len = strlen(tok);
	tok += (len + 1);

	len = strlen(tok);
	value = malloc(len);
	if (!value) {
		free(line);
		return NULL;
	}

	strncpy(value, tok, len-1);
	value[len-1] = '\0';

	free(line);
	return value;
}

static int count_values(const char *tok)
{
	int count = 0, i;

	for (i=0; i<strlen(tok); i++) {
		if (tok[i] == ' ')
			count++;
	}

	return count + 1;
}


static bool dtree_infodb_read_all(FILE *fp, struct dtree_infodb *infodb)
{
	char *data, *tmp, *tok;
	int count, i;

	data = dtree_infodb_read_value(fp, "all");
	if (!data)
		return false;

	count = count_values(data);

	infodb->alist.count = count;
	infodb->alist.attr = (struct dtree_attr *)calloc(count, sizeof(struct dtree_attr));
	if(!infodb->alist.attr)
		return false;

	tmp = data;
	for (i=0; i<infodb->alist.count; i++) {
		tok = strtok(tmp, " ");
		if (!tok)
			return false;

		assert(strlen(tok) < DTREE_ATTR_MAX_LEN);
		strcpy(infodb->alist.attr[i].name, tok);

		tmp = NULL;
	}

	free(data);
	return true;
}

static bool dtree_infodb_attr_parse(struct dtree_attr *attr, char *data)
{
	uint8_t *ptr;
	char *tok;
	int defined, i;

	tok = strtok(data, " ");
	if (!tok)
		return false;

	attr->type = dtree_attr_type_from_string(tok);
	if (attr->type == DTREE_ATTR_TYPE_UNKNOWN)
		return false;

	if (attr->type == DTREE_ATTR_TYPE_COMPLEX) {
		tok = strtok(NULL, " ");
		if (!tok)
			return false;

		attr->spec = strdup(tok);
		assert(attr->spec);

		attr->elem_size = dtree_attr_spec_size(attr->spec);
	} else if (attr->type == DTREE_ATTR_TYPE_STRING) {
		tok = strtok(NULL, " ");
		if (!tok)
			return false;

		attr->elem_size = atoi(tok);
	} else {
		attr->elem_size = dtree_attr_type_size(attr->type);
	}
	assert(attr->elem_size > 0);

	tok = strtok(NULL, " ");
	if (!tok)
		return false;

	attr->dim_count = atoi(tok);
	assert(attr->dim_count >= 0 && attr->dim_count <= 3);

	attr->count = 1;
	if (attr->dim_count > 0) {
		attr->dim = (int *)malloc(attr->dim_count * sizeof(int));
		assert(attr->dim);

		for (i=0; i<attr->dim_count; i++) {
			tok = strtok(NULL, " ");
			if (!tok)
				return false;

			attr->dim[i] = atoi(tok);
			assert(attr->dim[i] > 0);

			attr->count *= attr->dim[i];
		}
	}

	if (attr->type != DTREE_ATTR_TYPE_STRING && attr->type != DTREE_ATTR_TYPE_COMPLEX) {
		tok = strtok(NULL, " ");
		if (!tok)
			return false;

		attr->enum_count = atoi(tok);
		if (attr->enum_count > 0) {
			attr->aenum = (struct dtree_attr_enum *)malloc(attr->enum_count * sizeof(struct dtree_attr_enum));
			assert(attr->aenum);

			for (i=0; i<attr->enum_count; i++) {
				tok = strtok(NULL, " ");
				if (!tok)
					return false;

				attr->aenum[i].key = strdup(tok);
				assert(attr->aenum[i].key);

				tok = strtok(NULL, " ");
				if (!tok)
					return false;

				attr->aenum[i].value = strtoull(tok, NULL, 0);
			}
		}
	}

	tok = strtok(NULL, " ");
	if (!tok)
		return false;

	defined = atoi(tok);
	if (defined != 0 && defined != 1)
		return false;

	attr->value = (uint8_t *)calloc(attr->count, attr->elem_size);
	assert(attr->value);

	if (defined == 0)
		return true;

	ptr = attr->value;
	for (i=0; i<attr->count; i++) {
		if (attr->type == DTREE_ATTR_TYPE_COMPLEX) {
			uint64_t val;
			int elem_size, j;

			for (j=0; j<strlen(attr->spec); j++) {
				tok = strtok(NULL, " ");
				if (!tok)
					return false;

				val = strtoull(tok, NULL, 0);
				elem_size = attr->spec[j] - '0';
				dtree_attr_set_num(ptr, elem_size, val);
				ptr += elem_size;
			}
		} else if (attr->type == DTREE_ATTR_TYPE_STRING) {
			tok = strtok(NULL, " ");
			if (!tok)
				return false;

			dtree_attr_set_string(attr, ptr, tok);
			ptr += attr->elem_size;
		} else {
			tok = strtok(NULL, " ");
			if (!tok)
				return false;

			if (!dtree_attr_set_enum(attr, ptr, tok))
				dtree_attr_set_value(attr, ptr, tok);
			ptr += attr->elem_size;
		}
	}

	return true;
}

static bool dtree_infodb_read_attr(FILE *fp, struct dtree_infodb *infodb)
{
	char *data;
	int i;
	bool ok;

	for (i=0; i<infodb->alist.count; i++) {
		struct dtree_attr *attr = &infodb->alist.attr[i];

		data = dtree_infodb_read_value(fp, attr->name);
		if (!data)
			return false;

		ok = dtree_infodb_attr_parse(attr, data);

		free(data);

		if (!ok) {
			fprintf(stderr, "Failed to read %s\n", attr->name);
			return false;
		}
	}

	return true;
}

static bool dtree_infodb_read_targets(FILE *fp, struct dtree_infodb *infodb)
{
	char *data, *tmp, *tok;
	int count, i;

	data = dtree_infodb_read_value(fp, "targets");
	if (!data)
		return false;

	count = count_values(data);

	infodb->tlist.count = count;
	infodb->tlist.target = (struct dtree_target *)malloc(count * sizeof(struct dtree_target));
	if(!infodb->tlist.target)
		return false;

	tmp = data;
	for (i=0; i<infodb->tlist.count; i++) {
		tok = strtok(tmp, " ");
		if (!tok)
			return false;

		assert(strlen(tok) < DTREE_TARGET_MAX_LEN);
		strcpy(infodb->tlist.target[i].name, tok);

		tmp = NULL;
	}

	free(data);
	return true;
}

static bool dtree_infodb_read_target(FILE *fp, struct dtree_infodb *infodb)
{
	char *data, *tmp, *tok;
	int i, j;

	for (i=0; i<infodb->tlist.count; i++) {
		struct dtree_target *target = &infodb->tlist.target[i];

		data = dtree_infodb_read_value(fp, target->name);
		if (!data)
			return false;

		target->id_count = count_values(data);
		target->id = (int *)malloc(target->id_count * sizeof(int));
		if (!target->id)
			return false;

		tmp = data;
		for (j=0; j<target->id_count; j++) {
			tok = strtok(tmp, " ");
			if (!tok)
				return false;

			target->id[j] = atoi(tok);
			tmp = NULL;
		}

		free(data);
	}

	return true;
}

bool dtree_infodb_load(const char *filename, struct dtree_infodb *infodb)
{
	FILE *fp;
	bool rc;

	fp = fopen(filename, "r");
	if (!fp)
		return false;

	rc = dtree_infodb_read_all(fp, infodb);
	if (!rc)
		goto done;
	fprintf(stderr, "swetha: dtree_infodb_read_all success\n");
	rc = dtree_infodb_read_attr(fp, infodb);
	if (!rc)
		goto done;
    fprintf(stderr, "swetha: dtree_infodb_read_attr success\n");
	rc = dtree_infodb_read_targets(fp, infodb);
	if (!rc)
		goto done;
    fprintf(stderr, "swetha: dtree_infodb_read_targets success\n");
	rc = dtree_infodb_read_target(fp, infodb);
	if (!rc)
		goto done;
    fprintf(stderr, "swetha: dtree_infodb_read_target success\n");
done:
	fclose(fp);
	return rc;
}

struct dtree_attr *dtree_infodb_attr(struct dtree_infodb *infodb, const char *name)
{
	int i;

	for (i=0; i<infodb->alist.count; i++) {
		struct dtree_attr *attr = &infodb->alist.attr[i];
		if (strcmp(attr->name, name) == 0)
			return attr;
	}

	return NULL;
}
