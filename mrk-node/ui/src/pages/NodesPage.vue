<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import StatusBadge from '../components/StatusBadge.vue'
import TooltipBubble from '../components/TooltipBubble.vue'
import { useQuery } from '../composables/useQuery'
import { dateTime, duration, relativeTime } from '../utils/format'
import type { NodeList, NodeRecord } from '../types/rpc'

const status = ref('')
const availability = ref('')
const validator = ref(false)
const query = useQuery(() => rpc<NodeList>('node.list', {
  status: status.value || null,
  availability: availability.value || null,
  validator: validator.value,
  limit: 100,
}), [status, availability, validator])
let refreshClock: number | undefined
onMounted(() => {
  refreshClock = window.setInterval(() => { void query.refresh() }, 5_000)
})
onBeforeUnmount(() => {
  window.clearInterval(refreshClock)
})

function warmupRemaining(node: NodeRecord): string {
  const remaining = node.warmup_until - Math.floor(Date.now() / 1000)
  return remaining > 0 ? `${duration(remaining)} remaining` : 'Warmup period complete'
}

function warmupEnd(node: NodeRecord): string {
  const prefix = node.warmup_until > Math.floor(Date.now() / 1000) ? 'Ends' : 'Ended'
  return `${prefix} ${dateTime(node.warmup_until)}`
}
</script>

<template>
  <main class="page">
    <div class="page-heading">
      <div>
        <span class="eyebrow">Registry</span>
        <h1>Nodes</h1>
        <p>Public relay and validator registry.</p>
      </div>
      <div class="filters">
        <select v-model="status" aria-label="Filter node lifecycle">
          <option value="">All lifecycles</option>
          <option value="ACTIVE">Active</option>
          <option value="WARMING_UP">Warming up</option>
          <option value="DRAINING">Draining</option>
          <option value="SUSPENDED">Suspended</option>
          <option value="EXITED">Exited</option>
        </select>
        <select v-model="availability" aria-label="Filter node availability">
          <option value="">All availability</option>
          <option value="ONLINE">Online</option>
          <option value="PROBE_STALE">Probe stale</option>
          <option value="UNVERIFIED">Unverified</option>
          <option value="IP_SLOT_UNAVAILABLE">IP slot unavailable</option>
          <option value="EXIT_PENDING">Exit pending</option>
        </select>
        <label><input v-model="validator" type="checkbox" /> Validators only</label>
      </div>
    </div>
    <section class="panel">
      <QueryState :loading="query.loading.value" :error="query.error.value" :empty="!query.data.value?.nodes.length" @retry="query.refresh">
        <div v-if="query.data.value" class="table-wrap">
          <table>
            <thead><tr><th>Node</th><th>Lifecycle</th><th>Availability</th><th>Endpoint</th><th>Price / GiB</th><th>Last probe</th><th>Role</th></tr></thead>
            <tbody>
              <tr v-for="node in query.data.value.nodes" :key="node.node_id">
                <td><RouterLink :to="`/nodes/${node.node_id}`"><b>Node {{ node.node_id }}</b><small class="cell-note">{{ node.name }}</small></RouterLink></td>
                <td>
                  <TooltipBubble v-if="node.status === 'WARMING_UP'" :label="warmupRemaining(node)" :detail="warmupEnd(node)">
                    <StatusBadge :value="node.status" />
                  </TooltipBubble>
                  <StatusBadge v-else :value="node.status" />
                </td>
                <td><StatusBadge v-if="node.availability" :value="node.availability" /><span v-else>—</span></td>
                <td><code>{{ node.endpoint }}</code></td>
                <td>{{ node.price_per_gib_display }}</td>
                <td>{{ relativeTime(node.last_probe_success) }}</td>
                <td>{{ node.validator ? 'Validator' : node.validator_candidate ? 'Candidate' : 'Relay' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </QueryState>
    </section>
  </main>
</template>
