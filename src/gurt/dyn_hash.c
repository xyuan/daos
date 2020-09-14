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

#define DYNHASH_SIPBITS 6
#define DYNHASH_BUCKET	(1 << DYNHASH_SIPBITS)
#define DYNHASH_VECTOR	64
#define DYNHASH_MAGIC   0xab013245

#define _le64toh(x) (x)

typedef struct dh_field
{
	uint64_t	siphash;
	void 		*record;
} dh_field_t;

typedef struct dh_bucket
{
	unsigned char	counter;
	dh_field_t 	field[DYNHASH_BUCKET];
} dh_bucket_t;


#define ROTATE(x, b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define HALF_ROUND(a,b,c,d,s,t)     \
    a += b; c += d;                 \
    b = ROTATE(b, s) ^ a;           \
    d = ROTATE(d, t) ^ c;           \
    a = ROTATE(a, 32);

#define DOUBLE_ROUND(v0,v1,v2,v3)       \
    HALF_ROUND(v0,v1,v2,v3,13,16);      \
    HALF_ROUND(v2,v1,v0,v3,17,21);      \
    HALF_ROUND(v0,v1,v2,v3,13,16);      \
    HALF_ROUND(v2,v1,v0,v3,17,21);

const char keys[16] = { 0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf };

static uint64_t
siphash (const void *src, uint32_t src_sz)
{
	const uint64_t *_key = (uint64_t*) keys;
	uint64_t 	k0 = _le64toh(_key[0]);
	uint64_t 	k1 = _le64toh(_key[1]);
	uint64_t 	b = (uint64_t) src_sz << 56;
	const uint64_t 	*in = (uint64_t*) src;

	uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
	uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
	uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
	uint64_t v3 = k1 ^ 0x7465646279746573ULL;

	while (src_sz >= 8) {
	uint64_t mi = _le64toh(*in);
	in += 1;
	src_sz -= 8;
	v3 ^= mi;
	DOUBLE_ROUND(v0, v1, v2, v3);
	v0 ^= mi;
	}

	uint64_t t = 0;
	uint8_t *pt = (uint8_t*) &t;
	uint8_t *m = (uint8_t*) in;
	switch (src_sz) {
		case 7:
			pt[6] = m[6];
		case 6:
			pt[5] = m[5];
		case 5:
			pt[4] = m[4];
		case 4:
			*((uint32_t*) &pt[0]) = *((uint32_t*) &m[0]);
			break;
		case 3:
			pt[2] = m[2];
		case 2:
			pt[1] = m[1];
		case 1:
			pt[0] = m[0];
	}
	b |= _le64toh(t);

	v3 ^= b;
	DOUBLE_ROUND(v0, v1, v2, v3);
	v0 ^= b;
	v2 ^= 0xff;
	DOUBLE_ROUND(v0, v1, v2, v3);
	DOUBLE_ROUND(v0, v1, v2, v3);
	return (v0 ^ v1) ^ (v2 ^ v3);
}
static inline int
vec_init (dh_vector_t *vec, unsigned char power)
{
	int 	rc = 0;

	memset (vec, 0, sizeof *vec);
	vec->size = (size_t) (1 << power) * sizeof(void*);
	D_ALLOC_ARRAY(vec->data, 1 << power);
	if (vec->data == NULL) {
		rc = -DER_NOMEM;
	}
	return rc;
}
static inline void
vec_destroy (dh_vector_t *vec)
{
	if (vec->data != NULL) {
		D_FREE_PTR(vec->data);
	}
}
static inline int
vec_add (dh_vector_t *vec, void **in_data, uint32_t len)
{
	int 	rc = 0;
	size_t 	size = vec->size;
	size_t 	length = vec->counter * sizeof(void*);

	if (size < (length + len * sizeof(uint64_t*))) {
		rc = -DER_AGAIN;
	} else {
		memcpy (&vec->data[length], in_data, len * sizeof(uint64_t*));
		vec->counter += len;
	}
	return rc;
}
static inline void
vec_reset (dh_vector_t *vec)
{
	vec->counter = 0;
}
static inline int
vec_expand (dh_vector_t *vec)
{
	int	rc = 0;
	size_t	size = vec->size;
	void	**data;

	D_ALLOC(data, size * 2);
	if (data == NULL) {
		D_GOTO(out, rc = -DER_NOMEM);
	}
	//D_FREE_PTR(vec->data);
	vec->data = data;
	vec->size *= 2;
	vec->counter *= 2;
out:
	return rc;
}

static inline void
bucket_lock(struct dyn_hash *htable, uint32_t lock_index)
{
	lock_index %= htable->ht_bucket_locks;
	D_MUTEX_LOCK(&htable->ht_bmutex[lock_index]);
}
static inline void
bucket_unlock(struct dyn_hash *htable, uint32_t lock_index)
{
	lock_index %= htable->ht_bucket_locks;
	D_MUTEX_UNLOCK(&htable->ht_bmutex[lock_index]);
}
static void
no_bucket_lock(struct dyn_hash *htable, uint32_t lock_index)
{
}
static inline void
read_lock(struct dyn_hash *htable)
{
	D_RWLOCK_RDLOCK(&htable->ht_lock.rwlock);
}
static inline void
write_lock(struct dyn_hash *htable)
{
	D_RWLOCK_WRLOCK(&htable->ht_lock.rwlock);
}
static inline void
mutex_lock(struct dyn_hash *htable)
{
	D_MUTEX_LOCK(&htable->ht_lock.mutex);
}
static inline void
spinlock(struct dyn_hash *htable)
{
	D_SPIN_LOCK(&htable->ht_lock.spin);
}
static inline void
rw_unlock(struct dyn_hash *htable)
{
	D_RWLOCK_UNLOCK(&htable->ht_lock.rwlock);
}
static inline void
mutex_unlock(struct dyn_hash *htable)
{
	D_MUTEX_UNLOCK(&htable->ht_lock.mutex);
}
static inline void
spinunlock(struct dyn_hash *htable)
{
	D_SPIN_UNLOCK(&htable->ht_lock.spin);
}
static void no_global_lock(struct dyn_hash *htable)
{

}
static void
destroy_bucket_locks(struct dyn_hash *htable, uint32_t limit)
{
	uint32_t	idx;

	for (idx = 0; idx < limit; idx++) {
		D_MUTEX_DESTROY(&htable->ht_bmutex[idx]);
	}
}
/*----------Public API-------------------------*/
int
dyn_hash_create(uint32_t feats, uint32_t bits,
		dyn_hash_ops_t *hops, struct dyn_hash **htable_pp)
{
	struct dyn_hash		*htable;
	int			rc;

	D_ALLOC_PTR(htable);
	if (htable == NULL)
		D_GOTO(out, rc = -DER_NOMEM);

	rc = dyn_hash_table_create_inplace(feats, bits, hops, htable);
	if (rc)
		D_FREE(htable);
out:
	*htable_pp = htable;
	return rc;
}

int
dyn_hash_table_create_inplace(uint32_t feats, uint32_t bits,
		dyn_hash_ops_t *hops, struct dyn_hash *htable)
{
	int 		rc = 0;
	uint32_t	idx;
	dh_bucket_t     *bucket;

	D_ASSERT(hops != NULL);
	D_ASSERT(hops->hop_key_cmp != NULL);
	memset(htable, 0, sizeof *htable);
	htable->ht_feats = feats;
	htable->bucket_lock = no_bucket_lock;
	htable->bucket_unlock = no_bucket_lock;

	/* set global lock */
	htable->ht_write_lock = no_global_lock;
	htable->ht_read_lock = no_global_lock;
	if (!(feats & DYN_HASH_FT_NOLOCK)) {
		if (feats & DYN_HASH_FT_MUTEX) {
			rc = D_MUTEX_INIT(&htable->ht_lock.mutex, NULL);
			if( rc != 0 ){
				D_GOTO(out, rc);
			}
			htable->ht_write_lock = mutex_lock;
			htable->ht_read_lock = mutex_lock;
			htable->ht_rw_unlock = mutex_unlock;
		} else if (feats & DYN_HASH_FT_RWLOCK) {
			rc = D_RWLOCK_INIT(&htable->ht_lock.rwlock, NULL);
			if( rc != 0 ){
				D_GOTO(out, rc);
			}
			htable->ht_write_lock = write_lock;
			htable->ht_read_lock = read_lock;
			htable->ht_rw_unlock = rw_unlock;
		} else {
			rc = D_SPIN_INIT(&htable->ht_lock.spin,
					 PTHREAD_PROCESS_PRIVATE);
			if( rc != 0 ){
				D_GOTO(out, rc);
			}
			htable->ht_write_lock = spinlock;
			htable->ht_read_lock = spinlock;
			htable->ht_rw_unlock = spinunlock;
		}
	}

	/* create bucket locks if applicable */
	if (bits != 0 && !(feats & DYN_HASH_FT_NOLOCK)) {
		htable->ht_bucket_locks = (1 << bits); /* TO DO Do we need a limit here? */
		D_ALLOC_ARRAY(htable->ht_bmutex, htable->ht_bucket_locks);
		if (htable->ht_bmutex == NULL) {
			D_GOTO(out3, rc = -DER_NOMEM);
		}
		for(idx = 0; idx < htable->ht_bucket_locks; idx++) {
		        rc = D_MUTEX_INIT(&htable->ht_bmutex[idx], NULL);
		        if (rc != 0) {
		        	destroy_bucket_locks(htable, idx);
		        }
		        D_GOTO(out2, rc = -DER_INVAL);
		}
		/* set bucket lock virtual function */
		htable->bucket_lock = bucket_lock;
		htable->bucket_unlock = bucket_unlock;
	}
	/* initialize vector */
	htable->ht_ops = hops;
	rc = vec_init(&htable->ht_vector, DYNHASH_SIPBITS);
	if (rc != 0) {
		D_GOTO(out2, rc);
	}
	htable->ht_vector.counter = DYNHASH_BUCKET;

	/* allocate bucket */
	D_ALLOC(bucket, sizeof *bucket);
	if (bucket  == NULL) {
		D_GOTO(out1, rc = -DER_NOMEM);
	}
	memset(bucket, 0, sizeof *bucket);

	/* set bucket pointer to vector */
	for (idx = 0; idx < htable->ht_vector.counter; idx++) {
		htable->ht_vector.data[idx] = (void*)bucket;
	}
	htable->ht_magic = DYNHASH_MAGIC;

out3:
	if (!(feats & DYN_HASH_FT_NOLOCK)) {
		if (feats & DYN_HASH_FT_MUTEX) {
			rc = D_MUTEX_DESTROY(&htable->ht_lock.mutex);
		} else if (feats & DYN_HASH_FT_RWLOCK) {
			rc = D_RWLOCK_DESTROY(&htable->ht_lock.rwlock);
		} else {
			rc = D_SPIN_DESTROY(&htable->ht_lock.spin);
		}
	}
out2:
	if (htable->ht_bmutex != NULL) {
		D_FREE_PTR(htable->ht_bmutex);
	}

out1:
	vec_destroy(&htable->ht_vector);
out:
	return rc;
}

int
dyn_hash_table_traverse(struct dyn_hash *htable, dyn_hash_traverse_cb_t cb,
		void *arg)
{
	int 		rc = 0;
	uint32_t	idx;
	uint32_t        ix;
	dh_bucket_t     *bucket;
	dh_bucket_t     *prev = NULL;

	D_ASSERT(htable->ht_magic == DYNHASH_MAGIC);
	if (cb == NULL) {
		D_ERROR("invalid parameter, NULL cb.\n");
		D_GOTO(out, rc = -DER_INVAL);
	}

	htable->ht_read_lock(htable);
	for (idx = 0; idx < htable->ht_vector.counter; idx++) {
		bucket = htable->ht_vector.data[idx];
		if (bucket == prev) {
			continue;
		}
		prev = bucket;
		for (ix = 0; ix < bucket->counter; ix++) {
			rc = cb(bucket->field[idx].record, arg);
			if (rc != 0) {
				break;
			}
		}
	}
	htable->ht_rw_unlock(htable);
out:
	return rc;
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
