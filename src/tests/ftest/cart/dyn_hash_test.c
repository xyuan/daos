
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include "wrap_cmocka.h"
#include "gurt/common.h"
#include "gurt/list.h"
#include "gurt/heap.h"
#include "gurt/dlog.h"
#include "gurt/hash.h"
#include "gurt/atomic.h"
#include "gurt/dyn_hash.h"

typedef struct tSHTest
{
   uint32_t   key;
   uint64_t   sipkey;
   void*      value;
}tSHTest;

static bool dh_key_cmp(struct d_hash_table *ht, d_list_t *item, const void *key, unsigned int ksize)
{
	tSHTest *shtest = (tSHTest*)item;
	return memcmp(key, &shtest->key, sizeof shtest->key) == 0;
}
static bool dh_get_key(dh_item_t item, void **key, unsigned int *ksize)
{
	tSHTest *shtest = (tSHTest*)item;
	*key = &shtest->key;
	*ksize = sizeof shtest->key;
	return true;
}
static void dh_siphash_set(dh_item_t item, uint64_t siphash)
{
	tSHTest *shtest = (tSHTest*)item;
	shtest->sipkey = siphash;

}
static d_hash_table_ops_t hops = {
	.hop_key_cmp = 	dh_key_cmp,
	.hop_key_get = dh_get_key,
	.hop_siphash_set = dh_siphash_set,
};
int
main (int argc, char ** argv)
{
	uint32_t records = 1000000;
	struct d_hash_table *ht;
	uint64_t idx;
	int rc = 0;
	tSHTest *ht_test;
	tSHTest *found;

	rc = dyn_hash_create (D_HASH_FT_RWLOCK | D_HASH_FT_DYNAMIC,
			      10, NULL, &hops, &ht);
	if(rc != 0) {
		printf("%u - Error\n", __LINE__);
	}
	D_ALLOC(ht_test, sizeof *ht_test * records);
	if(ht_test == NULL) {
		printf("%u - Error\n", __LINE__);
	}
	for (idx = 0; idx < records; idx++) {
		ht_test[idx].key = idx;
		ht_test[idx].value = &ht_test[idx];
	}

        for (idx = 0; idx < records; idx++) {
        	rc = dyn_hash_rec_insert(ht, &ht_test[idx].key, sizeof ht_test[idx].key,
					 &ht_test[idx], true);
        	if(rc != 0) {
        		printf("%u -- rc=%d\n", __LINE__, rc);
        	}

        }
        if(ht->dyn_hash->ht_records != records) {
		printf("%u - Error\n", __LINE__);
        }

        for(idx = 0; idx < records; idx++) {
        	found = dyn_hash_rec_find(ht, &ht_test[idx].key, sizeof ht_test[idx].key, ht_test[idx].sipkey);
        	if(found == NULL){
        		printf("%u - Error\n", __LINE__);
        	}
        	if(found->key != ht_test[idx].key) {
        		printf("%u - Error\n", __LINE__);
        	}
        }
        for(idx = 0; idx < records; idx++) {
        	rc = dyn_hash_rec_delete_at(ht, ht_test[idx].value);
        	if(rc == 0) {
        		printf("%u - Error\n", __LINE__);
        	}
        }
	rc = dyn_hash_table_destroy(ht, false);
	if(rc != 0) {
		printf("%u - Error\n", __LINE__);
	}
	D_FREE(ht_test);
	return 0;
}
/*-----------------------------------*/
