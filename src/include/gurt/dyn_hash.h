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
 * \file
 *
 * Generic Dynamically Extended Hash Table APIs & data structures
 */

#ifndef __GURT_DYNHASH_H__
#define __GURT_DYNHASH_H__

#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>

#include <gurt/list.h>
#include <gurt/types.h>

/**
 * Hash table keeps and prints extra debugging information
 */
#define DYN_HASH_DEBUG	0

struct dyn_hash;
typedef void *dh_item_t;

#if defined(__cplusplus)
extern "C" {
#endif

/** @addtogroup GURT
 * @{
 */
/******************************************************************************
 * Generic Hash Table APIs / data structures
 ******************************************************************************/

typedef struct {
	/**
	 * Compare \p key with the  record
	 * This member function is mandatory.
	 *
	 * \param[in]	key	Key to compare
	 * \param[in]	ksize	Size of the key
	 *
	 * \retval	0	Success
	 * \retval	< 0	Invalid item
	 *
	 * \retval	true	The key of the record equals to \p key.
	 * \retval	false	No match
	 */
	bool (*hop_key_cmp)(dh_item_t item, const void *key, unsigned int ksize);
	/**
	 * Optional, store SIP hash associated with the item
	 * This member function avoid SIP hash caclulation for each
	 * insert / lookup call
	 * 
	 * \param[in] item item to store SIP hash
	 * \param[in] SIP hash
	 */
	void (*hop_siphash_set)(dh_item_t item, uint64_t siphash);
	/**
	 * Optional, increase refcount on the record
	 * If this function is provided, it will be called for successfully
	 * inserted record.
	 *
	 * \param[in]	htable	hash table
	 * \param[in]	item	The record being referenced.
	 */
	void (*hop_rec_addref)(struct dyn_hash *htable, dh_item_t *item);

	/**
	 * Optional, release refcount on the record \p link
	 *
	 * If this function is provided, it is called while deleting a record
	 * from the hash table.
	 *
	 * If hop_rec_free() is provided, this function can return true when
	 * the refcount reaches zero, in this case, hop_free() will be called.
	 * If the record should not be automatically freed by the hash table
	 * despite of refcount, then this function should never return true.
	 *
	 * \param[in]	htable	hash table
	 * \param[in]	item	The record being released.
	 *
	 * \retval	false	Do nothing
	 * \retval	true	Only if refcount is zero and the hash item
	 *			can be freed. If this function can return
	 *			true, then hop_rec_free() should be defined.
	 */
	bool (*hop_rec_decref)(struct dyn_hash *htable, dh_item_t item);

	/**
	 * Optional, release multiple refcount on the record \p link
	 *
	 * This function expands on hop_rec_decref() so the notes from that
	 * function apply here.  If hop_rec_decref() is not provided then
	 * hop_rec_ndecref() shouldn't be either.
	 *
	 * \param[in]	htable	hash table
	 * \param[in]	link	The link being released.
	 * \param[in]	count	The number of refcounts to be dropped.
	 *
	 * \retval	0	Do nothing
	 * \retval	1	Only if refcount is zero and the hash item
	 *			can be freed. If this function can return
	 *			true, then hop_rec_free() should be defined.
	 *		negative value on error.
	 */
	int (*hop_rec_ndecref)(struct dyn_hash *htable, dh_item_t item, int count);

	/**
	 * Optional, free the record
	 * It is called if hop_decref() returns zero.
	 *
	 * \param[in]	htable	hash table
	 * \param[in]	link	The record being freed.
	 */
	void (*hop_rec_free)(struct dyn_hash *htable, d_list_t *link);

} dyn_hash_ops_t;

enum dyn_hash_feats {
	/**
	 * By default, the hash table is protected by pthread_spinlock_t.
	 */

	/**
	 * The hash table has no lock, it means the hash table is protected
	 * by external lock, or only accessed by a single thread.
	 */
	DYN_HASH_FT_NOLOCK = (1 << 0),

	/**
	 * The hash table is protected by pthread_mutex_t.
	 */
	DYN_HASH_FT_MUTEX = (1 << 1),

	/**
	 * It is a read-mostly hash table, so it is protected by RW lock.
	 *
	 * Note: If caller sets this flag and also provides hop_addref/decref,
	 * then he should guarantee refcount changes are atomic or protected
	 * within hop_addref/decref, because RW lock can't protect refcount.
	 */
	DYN_HASH_FT_RWLOCK = (1 << 2),

	/**
	 * If the EPHEMERAL bit is zero:
	 * - The hash table will take and release references using the
	 *   user-provided hop_rec_addref and hop_rec_decref functions as
	 *   entries are added to and deleted from the hash table.
	 * - Decrementing the last reference on an item without previously
	 *   deleting it will cause an ASSERT - it will not be free'd
	 *
	 * If the EPHEMERAL bit is set:
	 * - The hash table will not call automatically call the addref or
	 *   decref functions when entries are added/removed
	 * - When decref is called and the reference count reaches zero, the
	 *   record will be deleted automatically from the table and free'd
	 *
	 * Note that if addref/decref are not provided this bit has no effect
	 */
	DYN_HASH_FT_EPHEMERAL = (1 << 3),

	/**
	 * Use Global Table Lock only instead of combination with bucket locking.
	 * Might be usefull for caching:
	 *  write lock
	 *  lookup
	 *  allocate if not found
	 *  insert in hash table
	 *  write unlock;
	 *  return found or allocated value
	 */
	DYN_HASH_FT_GLOCK = (1 << 15),
	
	/** Srink buckets and update vector during delete
	 *  If set all empty buckets getting deallocated
	 *  followed by vector update
	 *  This optimizes memory usage but increases record
	 *  remove time
	 */
	DYN_HASH_FT_SHRING = ( 1 << 14),
};

union dyn_hash_lock {
	pthread_spinlock_t spin;
	pthread_mutex_t mutex;
	pthread_rwlock_t rwlock;
};

typedef struct dh_vector {
	/** actual vector size (bytes) */
	size_t 		size;
	/** number of active bucket pointers */
	uint32_t	counter;
	/** set of buckect pointers */
	void		**data;
} dh_vector_t;

struct dyn_hash {
	/** bits to generate number of bucket mutexes */
	uint32_t		ht_bits;
	/** feature bits */
	uint32_t 		ht_feats;
	/** SIP hash right shift for vector index calculation */
	uint8_t 		ht_shift;
	/** total number of hash records */
	uint32_t 		ht_nr_max;
	/** vector (bucket pointer) */
	dh_vector_t 		ht_vector;
	/** different type of locks based on ht_feats */
	union dyn_hash_lock	ht_lock;
	/** customized member functions */
	dyn_hash_ops_t	*ht_ops;
#if D_HASH_DEBUG
	/** number of vector splits 
	 * (updated only if DYN_HASH_FT_SHRING not set)
	 */
	uint32_t		ht_vsplits;
	/** accumulated vector spit time (usec) 
	 * (updated only if DYN_HASH_FT_SHRING not set)
	 */
	uint32_t        	ht_vsplit_delay;	
#endif
};

/**
 * Create a new hash table.
 *
 * \note Please be careful while using rwlock and refcount at the same time,
 * see \ref d_hash_feats for the details.
 *
 * \param[in] feats		Feature bits, see DYN_HASH_FT_*
 * \param[in] bits		power2 (bits) for number of bucket mutexes
 *                      (ignored if DYN_HASH_FT_GLOCK is set)
  * \param[in] hops		Customized member functions
 * \param[out] htable_pp	The newly created hash table
 *
 * \return			0 on success, negative value on error
 */
int dyn_hash_create(uint32_t feats, uint32_t bits,
		dyn_hash_ops_t *hops, struct dyn_hash **htable_pp);

/**
 * Initialize an inplace hash table.
 *
 * Does not allocate the htable pointer itself
 *
 * \note Please be careful while using rwlock and refcount at the same time,
 * see \ref d_hash_feats for the details.
 *
 * \param[in] feats		Feature bits, see DYN_HASH_FT_*
 * \param[in] bits		power2 (bits) for number of bucket mutexes
 * \param[in] hops		Customized member functions
 * \param[in] htable	Hash table to be initialized
 *
 * \return			0 on success, negative value on error
 */
int dyn_hash_table_create_inplace(uint32_t feats, uint32_t bits,
		dyn_hash_ops_t *hops, struct dyn_hash *htable);

typedef int (*dyn_hash_traverse_cb_t)(dh_item_t item, void *arg);

/**
 * Traverse a hash table, call the traverse callback function on every item.
 * Break once the callback returns non-zero.
 *
 * \param[in] htable	The hash table to be finalised.
 * \param[in] cb		Traverse callback, will be called on every item
 *						in the hash table.
 *						See \a d_hash_traverse_cb_t.
 * \param[in] arg			Arguments for the callback.
 *
 * \return			zero on success, negative value if error.
 */
int dyn_hash_table_traverse(struct dyn_hash *htable, dyn_hash_traverse_cb_t cb,
		void *arg);

/**
 * Destroy a hash table.
 *
 * \param[in] htable	The hash table to be destroyed.
 * \param[in] force		true:
 *				Destroy the hash table even it is not empty,
 *				all pending items will be deleted.
 *				false:
 *				Destroy the hash table only if it is empty,
 *				otherwise returns error
 *
 * \return			zero on success, negative value if error.
 */
int dyn_hash_table_destroy(struct dyn_hash *htable, bool force);

/**
 * Finalise a hash table, reset all struct members.
 *
 * Note this does NOT free htable itself - only the members it contains.
 *
 * \param[in] htable		The hash table to be finalised.
 * \param[in] force		true:
 *				Finalise the hash table even it is not empty,
 *				all pending items will be deleted.
 *				false:
 *				Finalise the hash table only if it is empty,
 *				otherwise returns error
 *
 * \return			zero on success, negative value if error.
 */
int dyn_hash_table_destroy_inplace(struct dyn_hash *htable, bool force);

/**
 * lookup \p key in the hash table, the found chain link is returned on
 * success.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] key		The key to search
 * \param[in] ksize		Size of the key
 * \param[in] siphash   Previously generated SIP hash or 0 if unknown   
 *
 * \return			found item
 */
dh_item_t dyn_hash_rec_find(struct dyn_hash *htable, const void *key,
		unsigned int ksize, uint64_t siphash);

/**
 * Lookup \p key in the hash table, if there is a matched record, it should be
 * returned, otherwise the item will be inserted into the hash table. In the
 * later case, the returned is the is the input item.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] key		The key to be inserted
 * \param[in] ksize		Size of the key
 * \param[in] item		The item being inserted
 * \param[in] siphash   Previously generated SIP hash or 0 if unknown
 *
 * \return			matched record
 */
dh_item_t dyn_hash_rec_find_insert(struct dyn_hash *htable, const void *key,
		unsigned int ksize, dh_item_t item, uint64_t siphash);

/**
 * Insert a new key and its record into the hash table. The hash
 * table holds a refcount on the successfully inserted record, it releases the
 * refcount while deleting the record.
 *
 * If \p exclusive is true, it can succeed only if the key is unique, otherwise
 * this function returns error.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] key		The key to be inserted
 * \param[in] ksize		Size of the key
 * \param[in] item		The item being inserted
 * \param[in] siphash   Previously generated SIP hash or 0 if unknown
 * \param[in] exclusive		The key has to be unique if it is true.
 *
 * \return			0 on success, negative value on error
 */
int dyn_hash_rec_insert(struct dyn_hash *htable, const void *key,
		unsigned int ksize, dh_item_t item, uint64_t siphash, bool exclusive);

/**
 * Insert an anonymous record (w/o key) into the hash table.
 * This function calls hop_key_init() to generate a key for the new link
 * under the protection of the hash table lock.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] item		The link chain of the hash record
  *
 * \return			0 on success, negative value on error
 */
int dyn_hash_rec_insert_anonym(struct dyn_hash *htable, dh_item_t item);

/**
 * Delete the record identified by \p key from the hash table.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] key		The key of the record being deleted
 * \param[in] ksize		Size of the key
 * \param[in] siphash   Previously generated SIP hash or 0 if unknown
 *
 * \retval			true	Item with \p key has been deleted
 * \retval			false	Can't find the record by \p key
 */
bool dyn_hash_rec_delete(struct dyn_hash *htable, const void *key,
		unsigned int ksize, uint64_t siphash);

/**
 * Delete the record.
 * This record will be freed if hop_rec_free() is defined and the hash table
 * holds the last refcount.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] item		The link chain of the record
 *
 * \retval			true	Successfully deleted the record
 * \retval			false	The record has already been unlinked
 *					from the hash table
 */
bool dyn_hash_rec_delete_at(struct dyn_hash *htable, dh_item_t item);

/**
 * Evict the record identified by \p key from the hash table.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] key		The key of the record being evicted
 * \param[in] ksize		Size of the key
 *
 * \retval			true	Item with \p key has been evicted
 * \retval			false	Can't find the record by \p key
 */
bool dyn_hash_rec_evict(struct dyn_hash *htable, const void *key,
		unsigned int ksize);

/**
 * Evict the record.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] item		The record
 * \param[in] siphash   Previously generated SIP hash or 0 if unknown
 *
 * \retval			true	Item has been evicted
 * \retval			false	Not LRU feature
 */
bool dyn_hash_rec_evict_at(struct dyn_hash *htable, dh_item_t item, 
		uint64_t siphash);

/**
 * Increase the refcount of the record.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] item		The record
 */
void dyn_hash_rec_addref(struct dyn_hash *htable, dh_item_t item);

/**
 * Decrease the refcount of the record.
 * The record will be freed if hop_decref() returns true and the EPHEMERAL bit
 * is set.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] item		The record
 */
void dyn_hash_rec_decref(struct dyn_hash *htable, dh_item_t item);

/**
 * Decrease the refcount of the record by count.
 * The record will be freed if hop_decref() returns true.
 *
 * \param[in] htable		Pointer to the hash table
 * \param[in] count		Number of references to drop
 * \param[in] item		The hash record
 *
 * \retval			0		Success
 * \retval			-DER_INVAL	Not enough references were held.
 */
int dyn_hash_rec_ndecref(struct dyn_hash *htable, int count, dh_item_t item);

#if 0
/* can't be implemented in dyn_hash (no lists)
 *
 * Check if the link chain has already been unlinked from the hash table.
 *
 * \param[in] link		The link chain of the record
 *
 * \retval			true	Yes
 * \retval			false	No
 */
bool d_hash_rec_unlinked(d_list_t *link);
#endif

/**
 * Return the first entry in a hash table.
 *
 * Note this does not take a reference on the returned entry and has no ordering
 * semantics.  It's main use is for draining a hash table before calling
 * destroy()
 *
 * \param[in] htable		Pointer to the hash table
 *
 * \retval			item	Pointer to first element in hash table
 * \retval			NULL	Hash table is empty or error occurred
 */
dh_item_t dyn_hash_rec_first(struct dyn_hash *htable);

/**
 * If debugging is enabled, prints stats about the hash table
 *
 * \param[in] htable		Pointer to the hash table
 */
void dyn_hash_table_debug(struct dyn_hash *htable);

#if 0 /* Skip it for now */
/******************************************************************************
 * DAOS Handle Hash Table Wrapper
 *
 * Note: These functions are not thread-safe because reference counting
 * operations are not internally lock-protected. The user must add their own
 * locking.
 *
 ******************************************************************************/

#define D_HHASH_BITS		16
#define D_HTYPE_BITS		4
#define D_HTYPE_MASK		((1ULL << D_HTYPE_BITS) - 1)

/**
 * The handle type, uses the least significant 4-bits in the 64-bits hhash key.
 * The bit 0 is only used for D_HYTPE_PTR (pointer type), all other types MUST
 * set bit 0 to 1.
 */
enum {
	D_HTYPE_PTR = 0, /**< pointer type handle */
/* Must enlarge D_HTYPE_BITS to add more types */
};

struct d_hlink;
struct d_hlink_ops {
	/** free callback */
	void (*hop_free)(struct d_hlink *hlink);
};

struct d_rlink {
	d_list_t rl_link;
	uint32_t rl_ref;
	uint32_t rl_initialized :1;
};

struct d_hlink {
	struct d_rlink hl_link;
	uint64_t hl_key;
	struct d_hlink_ops *hl_ops;
};

struct d_hhash;
/**< internal definition */

int d_hhash_create(uint32_t feats, uint32_t bits, struct d_hhash **hhash);
void d_hhash_destroy(struct d_hhash *hhash);
void d_hhash_hlink_init(struct d_hlink *hlink, struct d_hlink_ops *hl_ops);
/**
 * Insert to handle hash table.
 * If \a type is D_HTYPE_PTR, user MUST ensure the bit 0 of \a hlink pointer is
 * zero. Assuming zero value of bit 0 of the pointer is reasonable portable. It
 * is with undefined result if bit 0 of \a hlink pointer is 1 for D_HTYPE_PTR
 * type.
 */
void d_hhash_link_insert(struct d_hhash *hhash, struct d_hlink *hlink,
		int type);
struct d_hlink* d_hhash_link_lookup(struct d_hhash *hhash, uint64_t key);
void d_hhash_link_getref(struct d_hhash *hhash, struct d_hlink *hlink);
void d_hhash_link_putref(struct d_hhash *hhash, struct d_hlink *hlink);
bool d_hhash_link_delete(struct d_hhash *hhash, struct d_hlink *hlink);
bool d_hhash_link_empty(struct d_hlink *hlink);
void d_hhash_link_key(struct d_hlink *hlink, uint64_t *key);
int d_hhash_key_type(uint64_t key);
bool d_hhash_key_isptr(uint64_t key);
int d_hhash_set_ptrtype(struct d_hhash *hhash);
bool d_hhash_is_ptrtype(struct d_hhash *hhash);

/******************************************************************************
 * UUID Hash Table Wrapper
 * Key: UUID
 * Value: generic pointer
 *
 * Note: These functions are not thread-safe because reference counting
 * operations are not internally lock-protected. The user must add their own
 * locking.
 *
 ******************************************************************************/

struct d_ulink;
struct d_ulink_ops {
	/** free callback */
	void (*uop_free)(struct d_ulink *ulink);
	/** optional compare callback -- for any supplement comparison */
	bool (*uop_cmp)(struct d_ulink *ulink, void *cmp_args);
};

struct d_ulink {
	struct d_rlink ul_link;
	struct d_uuid ul_uuid;
	struct d_ulink_ops *ul_ops;
};

int d_uhash_create(uint32_t feats, uint32_t bits, struct dyn_hash **htable);
void d_uhash_destroy(struct dyn_hash *htable);
void d_uhash_ulink_init(struct d_ulink *ulink, struct d_ulink_ops *ul_ops);
bool d_uhash_link_empty(struct d_ulink *ulink);
bool d_uhash_link_last_ref(struct d_ulink *ulink);
void d_uhash_link_addref(struct dyn_hash *htable, struct d_ulink *ulink);
void d_uhash_link_putref(struct dyn_hash *htable, struct d_ulink *ulink);
void d_uhash_link_delete(struct dyn_hash *htable, struct d_ulink *ulink);
int d_uhash_link_insert(struct dyn_hash *htable, struct d_uuid *key,
		void *cmp_args, struct d_ulink *ulink);
struct d_ulink* d_uhash_link_lookup(struct dyn_hash *htable, struct d_uuid *key,
		void *cmp_args);

#endif /* Skip it for now */
#if defined(__cplusplus)
}
#endif

/** @}
 */
#endif /*__GURT_DYNHASH_H__ */
