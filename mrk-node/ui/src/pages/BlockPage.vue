<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import EntityValue from '../components/EntityValue.vue'
import StatusBadge from '../components/StatusBadge.vue'
import DetailGrid from '../components/DetailGrid.vue'
import JsonPanel from '../components/JsonPanel.vue'
import { useQuery } from '../composables/useQuery'
import { dateTime, relativeTime } from '../utils/format'
import type { BlockOperations, BlockRecord } from '../types/rpc'

const route = useRoute()
const height = computed(() => Number(route.params.height))
const query = useQuery(() => Promise.all([
  rpc<BlockRecord>('block.get', { height: height.value }),
  rpc<BlockOperations>('block.operations', { height: height.value, limit: 50 }),
]).then(([block, operations]) => ({ block, operations })), [height])
</script>

<template><main class="page"><QueryState :loading="query.loading.value" :error="query.error.value" @retry="query.refresh"><template v-if="query.data.value"><div class="page-heading"><div><span class="eyebrow">Block</span><h1>#{{ query.data.value.block.height.toLocaleString() }}</h1><p>{{ dateTime(query.data.value.block.timestamp) }} · {{ relativeTime(query.data.value.block.timestamp) }}</p></div><StatusBadge :value="query.data.value.block.consensus_mode" /></div>
  <section class="panel detail-panel"><DetailGrid :rows="[{label:'Producer',value:`Node ${query.data.value.block.producer_node_id}`},{label:'Operations',value:query.data.value.block.operation_ids.length},{label:'Consensus round',value:query.data.value.block.consensus_round},{label:'Validator epoch',value:query.data.value.block.validator_epoch}]" />
    <div class="hash-rows"><div><span>Block hash</span><EntityValue :value="query.data.value.block.block_hash" :compact="false" /></div><div><span>Previous hash</span><EntityValue :value="query.data.value.block.previous_block_hash" :compact="false" /></div><div><span>State root</span><EntityValue :value="query.data.value.block.state_root" :compact="false" /></div></div>
  </section>
  <section class="panel"><div class="panel-heading"><div><span class="eyebrow">Included</span><h2>Operations</h2></div><span>{{ query.data.value.block.operation_ids.length.toLocaleString() }} total</span></div><div v-if="query.data.value.operations.operations.length" class="table-wrap"><table><thead><tr><th>Operation</th><th>Type</th><th>Signer</th><th>Status</th></tr></thead><tbody><tr v-for="operation in query.data.value.operations.operations" :key="operation.operation_id"><td><RouterLink :to="`/operations/${operation.operation_id}`"><EntityValue :value="operation.operation_id" /></RouterLink></td><td>{{ operation.kind }}</td><td><RouterLink :to="`/accounts/${operation.signer}`"><EntityValue :value="operation.signer" /></RouterLink></td><td><StatusBadge :value="operation.status" /></td></tr></tbody></table></div><div v-else class="query-state">This block contains no operations.</div></section>
  <JsonPanel :value="query.data.value.block" title="Raw block JSON" />
</template></QueryState></main></template>
