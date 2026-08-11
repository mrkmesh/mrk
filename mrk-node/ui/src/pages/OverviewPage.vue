<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted } from 'vue'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import StatusBadge from '../components/StatusBadge.vue'
import EntityValue from '../components/EntityValue.vue'
import { useQuery } from '../composables/useQuery'
import { relativeTime } from '../utils/format'
import type { BlockList, ChainStatus, NodeList, TreasuryStatus } from '../types/rpc'

interface OverviewData { chain: ChainStatus; blocks: BlockList; nodes: NodeList; treasury: TreasuryStatus }
const query = useQuery<OverviewData>(() => Promise.all([
  rpc<ChainStatus>('chain.status'),
  rpc<BlockList>('block.list', { limit: 8 }),
  rpc<NodeList>('node.list', { status: 'ACTIVE', limit: 6 }),
  rpc<TreasuryStatus>('treasury.status'),
]).then(([chain, blocks, nodes, treasury]) => ({ chain, blocks, nodes, treasury })))
let refreshClock: number | undefined
onMounted(() => {
  refreshClock = window.setInterval(() => { void query.refresh() }, 5_000)
})
onBeforeUnmount(() => {
  window.clearInterval(refreshClock)
})
const isLite = computed(() => (query.data.value?.chain.pruned_through_height ?? 0) > 0)
function availabilityHint(value: string | null): string | null {
  if (!value || value === 'ONLINE') return null
  return value.replaceAll('_', ' ').toLowerCase().replace(/(^|\s)\S/g, (letter) => letter.toUpperCase())
}
</script>

<template>
  <main class="page">
    <QueryState :loading="query.loading.value" :error="query.error.value" @retry="query.refresh">
      <template v-if="query.data.value">
        <div v-if="isLite" class="notice"><b>Limited history</b> This node retains blocks after height {{ query.data.value.chain.pruned_through_height.toLocaleString() }}.</div>
        <section class="hero-grid">
          <div class="hero-primary">
            <span class="eyebrow">Chain height</span>
            <strong>{{ query.data.value.chain.height.toLocaleString() }}</strong>
            <span>{{ relativeTime(query.data.value.chain.last_block_at) }}</span>
          </div>
          <div class="metric"><span>Consensus</span><StatusBadge :value="query.data.value.chain.mode" /></div>
          <div class="metric"><span>Validators</span><b>{{ query.data.value.chain.active_validator_count }}</b></div>
          <div class="metric"><span>Pending</span><b>{{ query.data.value.chain.pending_operation_count }}</b></div>
          <div class="metric"><span>Total burned</span><b>{{ query.data.value.chain.burned_display }}</b></div>
          <div class="metric"><span>Total settled traffic</span><b>{{ query.data.value.chain.total_settled_traffic_display }}</b></div>
        </section>

        <div class="section-grid">
          <section class="panel">
            <div class="panel-heading"><div><span class="eyebrow">Ledger</span><h1>Latest blocks</h1></div><RouterLink to="/blocks">View all</RouterLink></div>
            <div class="table-wrap"><table><thead><tr><th>Height</th><th>Age</th><th>Ops</th><th>Producer</th><th>Hash</th></tr></thead><tbody>
              <tr v-for="block in query.data.value.blocks.blocks" :key="block.height">
                <td><RouterLink :to="`/blocks/${block.height}`">{{ block.height.toLocaleString() }}</RouterLink></td>
                <td>{{ relativeTime(block.timestamp) }}</td><td>{{ block.operation_count }}</td>
                <td><RouterLink :to="`/nodes/${block.producer_node_id}`">Node {{ block.producer_node_id }}</RouterLink></td>
                <td><EntityValue :value="block.block_hash" /></td>
              </tr>
            </tbody></table></div>
          </section>

          <aside class="stack">
            <section class="panel compact-panel"><div class="panel-heading"><div><span class="eyebrow">Network</span><h2>Active nodes</h2></div><RouterLink to="/nodes">View all</RouterLink></div>
              <RouterLink v-for="node in query.data.value.nodes.nodes" :key="node.node_id" class="list-row" :to="`/nodes/${node.node_id}`"><span><b>Node {{ node.node_id }}</b><small>{{ node.name }}</small></span><span class="status-stack"><StatusBadge :value="node.status" /><small v-if="availabilityHint(node.availability)" class="availability-hint">{{ availabilityHint(node.availability) }}</small></span></RouterLink>
            </section>
            <section class="panel compact-panel"><span class="eyebrow">Protocol treasury</span><strong class="large-value">{{ query.data.value.treasury.balance_display }}</strong><RouterLink to="/treasury">Inspect treasury →</RouterLink></section>
          </aside>
        </div>
      </template>
    </QueryState>
  </main>
</template>
