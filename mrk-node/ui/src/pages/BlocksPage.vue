<script setup lang="ts">
import { ref } from 'vue'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import StatusBadge from '../components/StatusBadge.vue'
import EntityValue from '../components/EntityValue.vue'
import { useQuery } from '../composables/useQuery'
import { relativeTime } from '../utils/format'
import type { BlockList } from '../types/rpc'

const blocks = ref<BlockList['blocks']>([])
const cursor = ref<number | null>(null)
const query = useQuery(async () => {
  const page = await rpc<BlockList>('block.list', { limit: 30 })
  blocks.value = page.blocks
  cursor.value = page.next_cursor
  return page
})
const loadingMore = ref(false)
async function loadMore() {
  if (cursor.value === null) return
  loadingMore.value = true
  try {
    const page = await rpc<BlockList>('block.list', { cursor: cursor.value, limit: 30 })
    blocks.value.push(...page.blocks)
    cursor.value = page.next_cursor
  } finally { loadingMore.value = false }
}
</script>

<template><main class="page"><div class="page-heading"><div><span class="eyebrow">Ledger</span><h1>Blocks</h1><p>Finalized blocks retained by this node.</p></div><RouterLink class="button" to="/checkpoints">View checkpoints</RouterLink></div>
  <section class="panel"><QueryState :loading="query.loading.value" :error="query.error.value" :empty="!blocks.length" @retry="query.refresh"><div class="table-wrap"><table><thead><tr><th>Height</th><th>Age</th><th>Operations</th><th>Producer</th><th>Consensus</th><th>Hash</th></tr></thead><tbody><tr v-for="block in blocks" :key="block.height"><td><RouterLink :to="`/blocks/${block.height}`">{{ block.height.toLocaleString() }}</RouterLink></td><td>{{ relativeTime(block.timestamp) }}</td><td>{{ block.operation_count }}</td><td><RouterLink :to="`/nodes/${block.producer_node_id}`">Node {{ block.producer_node_id }}</RouterLink></td><td><StatusBadge :value="block.consensus_mode" /></td><td><EntityValue :value="block.block_hash" /></td></tr></tbody></table></div><div class="panel-footer"><button v-if="cursor !== null" class="button" type="button" :disabled="loadingMore" @click="loadMore">{{ loadingMore ? 'Loading…' : 'Load older blocks' }}</button><span v-else>End of retained history</span></div></QueryState></section>
</main></template>
