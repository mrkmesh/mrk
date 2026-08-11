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
import { dateTime, mrkAmount } from '../utils/format'
import type { OperationRecord } from '../types/rpc'

const route = useRoute()
const id = computed(() => String(route.params.id))
const query = useQuery(() => rpc<OperationRecord>('operation.get', { operation_id: id.value }), [id])
</script>

<template><main class="page"><QueryState :loading="query.loading.value" :error="query.error.value" @retry="query.refresh"><template v-if="query.data.value"><div class="page-heading"><div><span class="eyebrow">Operation</span><h1>{{ query.data.value.kind }}</h1><EntityValue :value="query.data.value.operation_id" :compact="false" /></div><StatusBadge :value="query.data.value.status" /></div>
  <section class="panel detail-panel"><DetailGrid :rows="[{label:'Created',value:dateTime(query.data.value.created_at)},{label:'Nonce',value:query.data.value.nonce},{label:'Block',value:query.data.value.block_height ?? 'Pending'},{label:'Status',value:query.data.value.status},{label:'Fee',value:mrkAmount(query.data.value.fee_charged)},{label:'Burned',value:mrkAmount(query.data.value.fee_burned)},{label:'To treasury',value:mrkAmount(query.data.value.fee_to_treasury)}]" /><div class="hash-rows"><div><span>Signer</span><RouterLink :to="`/accounts/${query.data.value.signer}`"><EntityValue :value="query.data.value.signer" :compact="false" /></RouterLink></div><div v-if="query.data.value.fee_payer"><span>Fee payer</span><RouterLink :to="`/accounts/${query.data.value.fee_payer}`"><EntityValue :value="query.data.value.fee_payer" :compact="false" /></RouterLink></div><div><span>Signature</span><EntityValue :value="query.data.value.signature" /></div></div></section>
  <section class="panel"><div class="panel-heading"><div><span class="eyebrow">Operation data</span><h2>Payload</h2></div></div><pre class="payload">{{ JSON.stringify(query.data.value.payload, null, 2) }}</pre></section><JsonPanel :value="query.data.value" title="Raw operation JSON" />
</template></QueryState></main></template>
