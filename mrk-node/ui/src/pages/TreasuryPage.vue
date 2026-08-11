<script setup lang="ts">
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import StatusBadge from '../components/StatusBadge.vue'
import EntityValue from '../components/EntityValue.vue'
import { useQuery } from '../composables/useQuery'
import { dateTime } from '../utils/format'

interface TreasuryStatus { balance_display: string; genesis_allocation_display: string; total_spent_display: string; spend_count: number; spending_enabled: boolean; current_single_spend_limit_display: string; ninety_day_spent_display: string; ninety_day_limit_display: string; annual_spent_display: string; annual_limit_display: string }
interface Spend { proposal_id: number; operation_id: string; recipient: string; amount_display: string; reference_hash: string; executed_at: number }
const query = useQuery(() => Promise.all([rpc<TreasuryStatus>('treasury.status'), rpc<Spend[]>('treasury.history', { limit: 100 })]).then(([status, history]) => ({ status, history })))
</script>

<template><main class="page"><QueryState :loading="query.loading.value" :error="query.error.value" @retry="query.refresh"><template v-if="query.data.value"><div class="page-heading"><div><span class="eyebrow">Protocol treasury</span><h1>{{ query.data.value.status.balance_display }}</h1><p>Keyless protocol funds controlled through governance.</p></div><StatusBadge :value="query.data.value.status.spending_enabled ? 'Spending enabled' : 'Spending locked'" /></div>
  <section class="summary-strip"><div><span>Genesis allocation</span><b>{{ query.data.value.status.genesis_allocation_display }}</b></div><div><span>Total spent</span><b>{{ query.data.value.status.total_spent_display }}</b></div><div><span>90-day usage</span><b>{{ query.data.value.status.ninety_day_spent_display }} / {{ query.data.value.status.ninety_day_limit_display }}</b></div><div><span>Annual usage</span><b>{{ query.data.value.status.annual_spent_display }} / {{ query.data.value.status.annual_limit_display }}</b></div></section>
  <section class="panel"><div class="panel-heading"><div><span class="eyebrow">Executed</span><h2>Spending history</h2></div><span>{{ query.data.value.status.spend_count }} spends</span></div><div v-if="query.data.value.history.length" class="table-wrap"><table><thead><tr><th>Proposal</th><th>Recipient</th><th>Amount</th><th>Executed</th><th>Operation</th></tr></thead><tbody><tr v-for="spend in query.data.value.history" :key="spend.operation_id"><td><RouterLink :to="`/governance/${spend.proposal_id}`">#{{ spend.proposal_id }}</RouterLink></td><td><RouterLink :to="`/accounts/${spend.recipient}`"><EntityValue :value="spend.recipient" /></RouterLink></td><td>{{ spend.amount_display }}</td><td>{{ dateTime(spend.executed_at) }}</td><td><RouterLink :to="`/operations/${spend.operation_id}`"><EntityValue :value="spend.operation_id" /></RouterLink></td></tr></tbody></table></div><div v-else class="query-state">No treasury spending has been executed.</div></section>
</template></QueryState></main></template>
