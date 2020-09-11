/*
 * (C) Copyright 2016-2020 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
/**
 * This file is part of cart, it implements the dynamic hash table functions.
 */
#define D_LOGFAC	DD_FAC(mem)
#include <gurt/common.h>
#include <gurt/list.h>
#include <gurt/dyn_hash.h>


int
dyn_hash_create(uint32_t feats, uint32_t bits,
		dyn_hash_ops_t *hops, struct dyn_hash **htable_pp)
{
	return 0;
}

int
dyn_hash_table_create_inplace(uint32_t feats, uint32_t bits,
		dyn_hash_ops_t *hops, struct dyn_hash *htable)
{
	return 0;
}

int
dyn_hash_table_traverse(struct dyn_hash *htable, dyn_hash_traverse_cb_t cb,
		void *arg)
{
	return 0;
}

int
dyn_hash_table_destroy(struct dyn_hash *htable, bool force)
{
	return 0;
}

int
dyn_hash_table_destroy_inplace(struct dyn_hash *htable, bool force)
{
	return 0;
}

dh_item_t
dyn_hash_rec_find(struct dyn_hash *htable, const void *key,
		unsigned int ksize, uint64_t siphash)
{
	return NULL;
}

dh_item_t
dyn_hash_rec_find_insert(struct dyn_hash *htable, const void *key,
		unsigned int ksize, dh_item_t item, uint64_t siphash)
{
	return NULL;
}

int
dyn_hash_rec_insert(struct dyn_hash *htable, const void *key,
		unsigned int ksize, dh_item_t item, uint64_t siphash, bool exclusive)
{
	return 0;
}

int
dyn_hash_rec_insert_anonym(struct dyn_hash *htable, dh_item_t item)
{
	return 0;
}

bool
dyn_hash_rec_delete(struct dyn_hash *htable, const void *key,
		unsigned int ksize, uint64_t siphash)
{
	return true;
}

bool
dyn_hash_rec_delete_at(struct dyn_hash *htable, dh_item_t item)
{
	return true;
}

bool
dyn_hash_rec_evict(struct dyn_hash *htable, const void *key,
		unsigned int ksize)
{
	return true;
}

bool
dyn_hash_rec_evict_at(struct dyn_hash *htable, dh_item_t item,
		uint64_t siphash)
{
	return true;
}

void
dyn_hash_rec_addref(struct dyn_hash *htable, dh_item_t item)
{

}

void
dyn_hash_rec_decref(struct dyn_hash *htable, dh_item_t item)
{

}

int
dyn_hash_rec_ndecref(struct dyn_hash *htable, int count, dh_item_t item)
{
	return 0;
}

dh_item_t
dyn_hash_rec_first(struct dyn_hash *htable)
{
	return NULL;
}

void
dyn_hash_table_debug(struct dyn_hash *htable)
{

}
