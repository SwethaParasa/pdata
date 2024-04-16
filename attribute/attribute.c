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
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libdtm/dtm.h"
#include "libdtree/dtree.h"
#include "libdtree/dtree_attr.h"
#include "libdtree/dtree_cronus.h"
#include "libdtree/dtree_dump.h"


static struct dtm_node *target_translate(struct dtm_node *root, const char *target)
{
	struct dtm_node *node = NULL;

	if (target[0] == '/') {
		node = dtm_find_node_by_path(root, target);
	} else {
		node = dtree_from_cronus_target(root, target);
	}

	return node;
}


static int do_create(const char *dtb, const char *infodb, const char *out_dtb)
{
	return dtree_create(dtb, infodb, out_dtb);
}


struct do_dump_state {
	const char *target;
	struct dtm_node *node;
	bool done;
	bool print;
};

static int do_dump_node(struct dtm_node *root, struct dtm_node *node, void *priv)
{
	struct do_dump_state *state = (struct do_dump_state *)priv;

	if (state->done)
		return 1;

	if (state->target) {
		state->node = target_translate(root, state->target);
		state->target = NULL;
	} else {
		state->print = true;
	}

	/* Single node */
	if (state->node && node == state->node) {
		state->done = true;
		state->print = true;
	}

	if (state->print)
		dtree_dump_print_node(node, stdout);

	return 0;
}

static int do_dump_attr(const struct dtree_attr *attr, void *priv)
{
	struct do_dump_state *state = (struct do_dump_state *)priv;

	if (!state->print)
		return 0;

	dtree_dump_print_attr_name(attr, stdout);

	if (attr->count <= 4) {
		dtree_dump_print_attr(attr, stdout);
	} else {
		printf("[%d]", attr->count);
	}

	printf("\n");

	return 0;
}

static int do_dump(const char *dtb, const char *infodb, const char *target)
{
	struct do_dump_state state;
	int ret;

	state = (struct do_dump_state) {
		.target = target,
		.done = false,
		.print = false,
	};

	ret = dtree_export(dtb, infodb, NULL, do_dump_node, do_dump_attr, &state);
	if (ret > 0)
		ret = 0;

	return ret;
}

static int do_export(const char *dtb, const char *infodb, const char *attrdb)
{
	return dtree_cronus_export(dtb, infodb, attrdb, stdout);
}

static int do_import(const char *dtb, const char *infodb, const char *dump_file)
{
	FILE *fp;
	int ret;

	fp = fopen(dump_file, "r");
	fprintf(stderr, "swetha: Trying to open cronus dump file %s\n", dump_file);
	if (!fp) {
		fprintf(stderr, "Failed to open cronus dump file %s\n", dump_file);
		return 1;
	}
    fprintf(stderr, "swetha: Successfully opened cronus dump file %s\n", dump_file);
	ret = dtree_cronus_import(dtb, infodb, fp);
	fclose(fp);
	return ret;
}

struct do_read_state {
	const char *target;
	const char *attr_name;

	struct dtm_node *node;
	bool matched;
};

static int do_read_node(struct dtm_node *root, struct dtm_node *node, void *priv)
{
	struct do_read_state *state = (struct do_read_state *)priv;

	if (state->matched)
		return 1;

	if (state->target) {
		state->node = target_translate(root, state->target);
		if (!state->node) {
			fprintf(stderr, "No such target %s\n", state->target);
			return -1;
		}
		state->target = NULL;
	}

	if (state->node && node == state->node) {
		state->matched = true;
	}

	return 0;
}

static int do_read_attr(const struct dtree_attr *attr, void *priv)
{
	struct do_read_state *state = (struct do_read_state *)priv;

	if (!state->matched)
		return 0;

	if (strcmp(attr->name, state->attr_name) == 0) {
		dtree_dump_print_attr_name(attr, stdout);
		printf(" = ");
		dtree_dump_print_attr(attr, stdout);
		printf("\n");
		return 1;
	}

	return 0;
}

static int do_read(const char *dtb, const char *infodb, const char *target, const char *attr_name)
{
	struct do_read_state state;
	int ret;

	state = (struct do_read_state) {
		.target = target,
		.attr_name = attr_name,
		.matched = false,
	};

	ret = dtree_export(dtb, infodb, NULL, do_read_node, do_read_attr, &state);
	if (ret == 0) {
		fprintf(stderr, "No such attribute %s\n", attr_name);
		return 1;
	}
	if (ret > 0)
		ret = 0;

	return ret;
}

static int do_translate(const char *dtb, const char *target)
{
	struct dtm_file *dfile;
	struct dtm_node *root, *node;
	char *path;

	dfile = dtm_file_open(dtb, false);
	if (!dfile)
		return 1;

	root = dtm_file_read(dfile);
	dtm_file_close(dfile);
	if (!root)
		return 1;

	node = target_translate(root, target);
	if (!node) {
		fprintf(stderr, "Failed to translate %s\n", target);
		return 2;
	}

	if (target[0] == '/') {
		path = dtree_to_cronus_target(root, node);
	} else {
		path = dtm_node_path(node);
	}

	if (!path) {
		fprintf(stderr, "Failed to translate %s\n", target);
		return 2;
	}

	printf("%s ---> %s\n", target, path);
	free(path);

	return 0;
}

struct do_write_state {
	const char *target;
	const char *attr_name;
	const char **argv;
	int argc;

	struct dtm_node *root;
	struct dtm_node *node;
	struct dtree_attr *attr;
};

static int do_write_parse(void *ctx, void *priv)
{
	struct do_write_state *state = (struct do_write_state *)priv;
	struct dtree_attr *attr;
	uint8_t *ptr;
	int count, ret, i;

	state->root = dtree_import_root(ctx);
	state->node = target_translate(state->root, state->target);
	if (!state->node) {
		fprintf(stderr, "No such target %s\n", state->target);
		return -1;
	}

	dtree_import_set_node(state->node, ctx);

	ret = dtree_import_attr(state->attr_name, ctx, &attr);
	if (ret < 0) {
		fprintf(stderr, "No such attribute %s\n", state->attr_name);
		return -1;
	}
	state->attr = attr;

	count = attr->count;
	if (attr->type == DTREE_ATTR_TYPE_COMPLEX)
		count *= strlen(attr->spec);

	if (state->argc != count) {
		fprintf(stderr, "Insufficient values %d, expected %d\n", state->argc, count);
		return -1;
	}

	ptr = attr->value;
	for (i=0; i<attr->count; i++) {
		if (attr->type == DTREE_ATTR_TYPE_COMPLEX) {
			uint64_t val;
			int data_size, j;

			count = i * strlen(attr->spec);

			for (j=0; j<strlen(attr->spec); j++) {
				val = strtoull(state->argv[count+j], NULL, 0);
				data_size = attr->spec[j] - '0';
				dtree_attr_set_num(ptr, data_size, val);
				ptr += data_size;
			}

		} else if (attr->type == DTREE_ATTR_TYPE_STRING) {
			if (strlen(state->argv[i]) > attr->elem_size) {
				fprintf(stderr, "Value too long %zu, expected %d\n", strlen(state->argv[i]), attr->elem_size);
				return -1;
			}
			dtree_attr_set_string(attr, ptr, state->argv[i]);
			ptr += attr->elem_size;

		} else {
			if (!dtree_attr_set_enum(attr, ptr, state->argv[i]))
				dtree_attr_set_value(attr, ptr, state->argv[i]);
			ptr += attr->elem_size;
		}

		ret = dtree_import_attr_update(ctx);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int do_write_export(struct do_write_state *state)
{
	FILE *fp;
	const char *override;
	char *path;

	override = getenv("PDATA_ATTR_OVERRIDE");
	if (!override)
		return 0;

	path = dtree_to_cronus_target(state->root, state->node);
	if (!path) {
		fprintf(stderr, "Failed to translate node\n");
		return -1;
	}

	fp = fopen(override, "a");
	if (!fp) {
		fprintf(stderr, "Failed to open %s in append mode\n", override);
		return -1;
	}

	dtree_cronus_print_node(path, fp);
	dtree_cronus_print_attr(state->attr, fp);

	free(path);
	fclose(fp);
	return 0;
}

static int do_write(const char *dtb, const char *infodb, const char *target,
		    const char *attr_name, const char **argv, int argc)
{
	struct do_write_state state;
	int rc;

	state = (struct do_write_state) {
		.target = target,
		.attr_name = attr_name,
		.argv = argv,
		.argc = argc,
	};

	rc = dtree_import(dtb, infodb, do_write_parse, &state);
	if (rc != 0)
		return rc;

	return do_write_export(&state);
}

static void bmc_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s export [<attr-list>]\n", prog);
	fprintf(stderr, "       %s import <attr-dump>\n", prog);
	fprintf(stderr, "       %s read <target> <attribute>\n", prog);
	fprintf(stderr, "       %s write <target> <attribute> <value>\n", prog);
	fprintf(stderr, "       %s translate <target>\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  <attr-list>   - Filename containing list of attribute names to export\n");
	fprintf(stderr, "  <attr-dump>   - Filename containing targets and attribute values\n");
	fprintf(stderr, "  <target>      - Device tree target\n");
	fprintf(stderr, "                  e.g. p10:k0:n0:s0:p00 (cronus) or /proc0 (device tree path)\n");
	fprintf(stderr, "  <attribute>   - Name of an attribute\n");
	fprintf(stderr, "  <value>       - Value of the attribute\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Sub-Command:\n");
	fprintf(stderr, "  export        - Used to print all attribute values\n");
	fprintf(stderr, "                  e.g. %s export > attributes_dump.txt\n", prog);
	fprintf(stderr, "  import        - Used to update device tree with attribute values\n");
	fprintf(stderr, "                  e.g. %s import attributes_dump.txt\n", prog);
	fprintf(stderr, "  read          - Used to print a single attribute value for a target\n");
	fprintf(stderr, "                  e.g. %s read p10:k0:n0:s0:p00 ATTR_NAME\n", prog);
	fprintf(stderr, "  write         - Used to modify a single attribute value for a target\n");
	fprintf(stderr, "                  e.g. %s write p10:k0:n0:s0:p00 ATTR_NAME <value>\n", prog);
	fprintf(stderr, "  translate     - Used to translate target name between cronus and device tree\n");
	fprintf(stderr, "                  e.g. %s translate p10:k0:n0:s0:p00\n", prog);
	fprintf(stderr, "                  e.g. %s translate /proc0\n", prog);
	fprintf(stderr, "\n");

	exit(1);
}

static int bmc_main(const char *dtb, const char *infodb, int argc, const char **argv)
{
	int ret = -1;

	if (argc < 2)
		bmc_usage(argv[0]);

	if (strcmp(argv[1], "export") == 0) {
		if (argc != 2 && argc != 3)
			bmc_usage(argv[0]);

		if (argc == 2)
			ret = do_export(dtb, infodb, NULL);
		else
			ret = do_export(dtb, infodb, argv[2]);

	} else if (strcmp(argv[1], "import") == 0) {
		if (argc != 3)
			bmc_usage(argv[0]);

		ret = do_import(dtb, infodb, argv[2]);

	} else if (strcmp(argv[1], "read") == 0) {
		if (argc != 4)
			bmc_usage(argv[0]);

		ret = do_read(dtb, infodb, argv[2], argv[3]);

	} else if (strcmp(argv[1], "translate") == 0) {
		if (argc != 3)
			bmc_usage(argv[0]);

		ret = do_translate(dtb, argv[2]);

	} else if (strcmp(argv[1], "write") == 0) {
		if (argc < 5)
			bmc_usage(argv[0]);

		ret = do_write(dtb, infodb, argv[2], argv[3], &argv[4], argc-4);

	} else {
		bmc_usage(argv[0]);
	}

	return ret;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s create <dtb> <infodb> <out-dtb>\n", prog);
	fprintf(stderr, "       %s dump <dtb> <infodb> [<target>]\n", prog);
	fprintf(stderr, "       %s export <dtb> <infodb> [<attr-list>]\n", prog);
	fprintf(stderr, "       %s import <dtb> <infodb> <attr-dump>\n", prog);
	fprintf(stderr, "       %s read <dtb> <infodb> <target> <attribute>\n", prog);
	fprintf(stderr, "       %s translate <dtb> <target>\n", prog);
	fprintf(stderr, "       %s write <dtb> <infodb> <target> <attribute> <value>\n", prog);
	exit(1);
}

int main(int argc, const char **argv)
{
	const char *dtb, *infodb;
	int ret = -1;

	dtb = getenv("PDBG_DTB");
	infodb = getenv("PDATA_INFODB");
	if (dtb && infodb) {
		return bmc_main(dtb, infodb, argc, argv);
	}

	if (argc < 2)
		usage(argv[0]);

	if (strcmp(argv[1], "create") == 0) {
		if (argc != 5)
			usage(argv[0]);

		ret = do_create(argv[2], argv[3], argv[4]);

	} else if (strcmp(argv[1], "dump") == 0) {
		if (argc != 4 && argc != 5)
			usage(argv[0]);

		if (argc == 4)
			ret = do_dump(argv[2], argv[3], NULL);
		else
			ret = do_dump(argv[2], argv[3], argv[4]);

	} else if (strcmp(argv[1], "export") == 0) {
		if (argc != 4 && argc != 5)
			usage(argv[0]);

		if (argc == 4)
			ret = do_export(argv[2], argv[3], NULL);
		else
			ret = do_export(argv[2], argv[3], argv[4]);

	} else if (strcmp(argv[1], "import") == 0) {
		if (argc != 5)
			usage(argv[0]);

		ret = do_import(argv[2], argv[3], argv[4]);

	} else if (strcmp(argv[1], "read") == 0) {
		if (argc != 6)
			usage(argv[0]);

		ret = do_read(argv[2], argv[3], argv[4], argv[5]);

	} else if (strcmp(argv[1], "translate") == 0) {
		if (argc != 4)
			usage(argv[0]);

		ret = do_translate(argv[2], argv[3]);

	} else if (strcmp(argv[1], "write") == 0) {
		if (argc < 7)
			usage(argv[0]);

		ret = do_write(argv[2], argv[3], argv[4], argv[5], &argv[6], argc-6);

	} else {
		usage(argv[0]);
	}

	return ret;
}
