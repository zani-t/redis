#include <cassert>
#include <stdlib.h>

#include "hashtable.h"

const size_t k_resizing_work = 128;
const size_t k_max_load_factor = 8;

// Initialize - indexing done using bit mask & hash code*
static void h_init(HTab *htab, size_t n) {
    // Assert size of hashtable n = 2^k & init array size n
    assert(n > 0 && ((n - 1) & (n == 0)));
    htab->tab = (HNode **)calloc(sizeof(HNode *), n);
    htab->mask = n - 1;
    htab->size = 0;
}

// Hashtable insertion
static void h_insert(HTab *htab, HNode *node) {
    // Produce position from hashcode & bitmask
    size_t pos = node->hcode & htab->mask;
    // Get foremost element in position and insert new node
    HNode *next = htab->tab[pos];
    node->next = next;
    htab->tab[pos] = node;
    htab->size++;
}

// Lookup subroutine - return parent pointer of target node
static HNode **h_lookup(
    HTab *htab, HNode *key, bool (*cmp)(HNode *, HNode *))
{
    if (!htab->tab)
        return NULL;
    
    size_t pos = key->hcode & htab->mask;
    // Get ptr to node/linked list
    HNode **from = &htab->tab[pos];
    while (*from) {
        if (cmp(*from, key))
            return from;
        from = &(*from)->next;
    }
    return NULL;
}

// Remove
static HNode *h_detach(HTab *htab, HNode **from) {
    HNode *node = *from;
    *from = (*from)->next;
    htab->size--;
    return node;
}

// Move nodes
static void hm_help_resizing(HMap *hmap) {
    if (hmap->ht2.tab == NULL)
        return;
    
    size_t nwork = 0;

    // Migrate max 128 nodes
    while (nwork < k_resizing_work && hmap->ht2.size > 0) {
        // Scan ht2 and move nodes to ht1
        HNode **from = &hmap->ht2.tab[hmap->resizing_pos];
        if (!*from) {
            hmap->resizing_pos++;
            continue;
        }

        h_insert(&hmap->ht1, h_detach(&hmap->ht2, from));
        nwork++;
    }

    if (hmap->ht2.size == 0) {
        // Finished
        free(hmap->ht2.tab);
        hmap->ht2 = HTab();
    }
}

// Called when resizing required - create larger hashtable & swap
static void hm_start_resizing(HMap *hmap) {
    assert(hmap->ht2.tab == NULL);
    hmap->ht2 = hmap->ht1;
    h_init(&hmap->ht1, (hmap->ht1.mask + 1) * 2);
    hmap->resizing_pos = 0;
}

// Check for need to resize and trigger node insertion
void hm_insert(HMap *hmap, HNode *node) {
    if (!hmap->ht1.tab)
        h_init(&hmap->ht1, 4);
    h_insert(&hmap->ht1, node);

    if (!hmap->ht2.tab) {
        // Check whether resizing is needed
        size_t load_factor = hmap->ht1.size / (hmap->ht1.mask + 1);
        if (load_factor >= k_max_load_factor)
            hm_start_resizing(hmap);
    }
    hm_help_resizing(hmap);
}

// Key lookup
HNode *hm_lookup (
    HMap *hmap, HNode *key, bool (*cmp)(HNode *, HNode *))
{
    hm_help_resizing(hmap);
    HNode **from = h_lookup(&hmap->ht1, key, cmp);
    if (!from)
        from = h_lookup(&hmap->ht2, key, cmp);
    return from ? *from : NULL;
}

// Key removal
HNode *hm_pop(
    HMap *hmap, HNode *key, bool(*cmp)(HNode *, HNode *))
{
    hm_help_resizing(hmap);
    HNode **from = h_lookup(&hmap->ht1, key, cmp);
    if (from)
        return h_detach(&hmap->ht1, from);
    from = h_lookup(&hmap->ht2, key, cmp);
    if (from)
        return h_detach(&hmap->ht2, from);
    return NULL;
}

size_t hm_size(HMap *hmap) {
    return hmap->ht1.size + hmap->ht2.size;
}

void hm_destroy(HMap *hmap) {
    assert(hmap->ht1.size + hmap->ht2.size == 0);
    free(hmap->ht1.tab);
    free(hmap->ht2.tab);
    *hmap = HMap{};
}