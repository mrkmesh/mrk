<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import EntityValue from '../components/EntityValue.vue'
import StatusBadge from '../components/StatusBadge.vue'
import DetailGrid from '../components/DetailGrid.vue'
import JsonPanel from '../components/JsonPanel.vue'
import { useQuery } from '../composables/useQuery'
import { dateTime } from '../utils/format'
import type { NodeRecord } from '../types/rpc'

const route = useRoute()
const nodeId = computed(() => Number(route.params.id))
const query = useQuery(() => rpc<NodeRecord>('node.get', { node_id: nodeId.value }), [nodeId])
let refreshClock: number | undefined

function paymentWindowSize(bytes: number): string {
  const mebibytes = bytes / (1024 * 1024)
  const display = Number.isInteger(mebibytes) ? mebibytes.toString() : mebibytes.toFixed(2).replace(/0+$/, '').replace(/\.$/, '')
  return `${display} MiB (${bytes.toLocaleString()} bytes)`
}

onMounted(() => {
  refreshClock = window.setInterval(() => { void query.refresh() }, 5_000)
})
onBeforeUnmount(() => {
  window.clearInterval(refreshClock)
})
</script>

<template>
  <main class="page">
    <QueryState :loading="query.loading.value" :error="query.error.value" @retry="query.refresh">
      <template v-if="query.data.value">
        <div class="page-heading">
          <div><span class="eyebrow">Registry node</span><h1>Node {{ query.data.value.node_id }}</h1><p>{{ query.data.value.name }}</p></div>
          <div class="heading-badges"><StatusBadge :value="query.data.value.status" /><StatusBadge v-if="query.data.value.availability" :value="query.data.value.availability" /></div>
        </div>
        <section class="panel detail-panel">
          <DetailGrid :rows="[
            { label: 'Role', value: query.data.value.validator ? 'Validator' : query.data.value.validator_candidate ? 'Candidate' : 'Relay' },
            { label: 'Registered', value: dateTime(query.data.value.registered_at) },
            { label: 'Probe successes', value: query.data.value.probe_success_count },
            { label: 'Probe valid until', value: dateTime(query.data.value.probe_valid_until) },
            { label: 'Offline exit at', value: dateTime(query.data.value.offline_exit_at) },
            { label: 'Service bond', value: query.data.value.service_bond_display },
            { label: 'Governance bond', value: query.data.value.governance_bond_display },
            { label: 'Relay capability revision', value: query.data.value.relay_capability_revision },
            { label: 'Payment window bytes', value: paymentWindowSize(query.data.value.payment_window_bytes) },
            { label: 'Payment window time', value: `${query.data.value.payment_window_seconds}s` },
          ]" />
          <div class="hash-rows">
            <div><span>Endpoint</span><code>{{ query.data.value.endpoint }}</code></div>
            <div><span>Reward IP</span><code>{{ query.data.value.reward_ip }}</code></div>
            <div><span>IP slot</span><span>{{ query.data.value.owns_ip_slot ? 'Owned by this node' : 'Unavailable' }}<template v-if="query.data.value.ip_slot_reusable_at"> · reusable {{ dateTime(query.data.value.ip_slot_reusable_at) }}</template></span></div>
            <div><span>Owner</span><RouterLink :to="`/accounts/${query.data.value.owner_address}`"><EntityValue :value="query.data.value.owner_address" :compact="false" /></RouterLink></div>
          </div>
        </section>
        <JsonPanel :value="query.data.value" title="Raw node JSON" />
      </template>
    </QueryState>
  </main>
</template>
