<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import EntityValue from '../components/EntityValue.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { useQuery } from '../composables/useQuery'
import { relativeTime } from '../utils/format'
import type { Balance, OperationRecord } from '../types/rpc'

const route = useRoute()
const address = computed(() => String(route.params.address))
const query = useQuery(() => Promise.all([
  rpc<Balance>('account.balance', { address: address.value }),
  rpc<OperationRecord[]>('account.history', { address: address.value, limit: 50 }),
]).then(([balance, history]) => ({ balance, history })), [address])
</script>

<template><main class="page"><QueryState :loading="query.loading.value" :error="query.error.value" @retry="query.refresh"><template v-if="query.data.value"><div class="page-heading"><div><span class="eyebrow">Account</span><h1>{{ query.data.value.balance.balance_display }}</h1><EntityValue :value="query.data.value.balance.address" :compact="false" /></div><div class="metric"><span>Nonce</span><b>{{ query.data.value.balance.nonce }}</b></div></div>
  <section class="panel"><div class="panel-heading"><div><span class="eyebrow">Activity</span><h2>Recent operations</h2></div></div><div v-if="query.data.value.history.length" class="table-wrap"><table><thead><tr><th>Operation</th><th>Type</th><th>Age</th><th>Block</th><th>Status</th></tr></thead><tbody><tr v-for="operation in query.data.value.history" :key="operation.operation_id"><td><RouterLink :to="`/operations/${operation.operation_id}`"><EntityValue :value="operation.operation_id" /></RouterLink></td><td>{{ operation.kind }}</td><td>{{ relativeTime(operation.created_at) }}</td><td><RouterLink v-if="operation.block_height" :to="`/blocks/${operation.block_height}`">{{ operation.block_height }}</RouterLink><span v-else>—</span></td><td><StatusBadge :value="operation.status" /></td></tr></tbody></table></div><div v-else class="query-state">No retained operations for this account.</div></section>
</template></QueryState></main></template>
