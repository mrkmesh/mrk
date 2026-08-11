<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { useQuery } from '../composables/useQuery'
import { dateTime, duration, relativeTime } from '../utils/format'
import type { GovernanceProposal } from '../types/rpc'

interface ScheduledParameterChange {
  effective_epoch: number
  value: string
}

interface GovernanceParameter {
  name: string
  category: string
  governance: 'STANDARD' | 'CRITICAL'
  current_value: string
  configured_value: string
  scheduled_changes: ScheduledParameterChange[]
}

interface GovernanceStatus {
  mode: string
  governance_eligible_count: number
  threshold: number
  critical_threshold: number
  node1_direct_end_threshold: number
  emission_paused: boolean
  availability_mode: string
  current_epoch_number: number
  current_epoch_started_at: number
  current_epoch_ends_at: number
  current_epoch_seconds: number
  current_epoch_mint_amount_display: string
  current_reward_immediate_bps: number
  current_reward_vesting_seconds: number
  parameters: GovernanceParameter[]
}

const query = useQuery(() => Promise.all([
  rpc<GovernanceStatus>('governance.status'),
  rpc<GovernanceProposal[]>('governance.list'),
]).then(([status, proposals]) => ({ status, proposals: proposals.reverse() })))
const now = ref(Math.floor(Date.now() / 1000))
let clock: number | undefined
let refreshClock: number | undefined

onMounted(() => {
  clock = window.setInterval(() => { now.value = Math.floor(Date.now() / 1000) }, 1_000)
  refreshClock = window.setInterval(() => { void query.refresh() }, 5_000)
})
onBeforeUnmount(() => {
  window.clearInterval(clock)
  window.clearInterval(refreshClock)
})

const remaining = computed(() => query.data.value
  ? query.data.value.status.current_epoch_ends_at - now.value
  : 0)
const progress = computed(() => {
  const status = query.data.value?.status
  if (!status) return 0
  return Math.min(100, Math.max(
    0,
    (now.value - status.current_epoch_started_at) / status.current_epoch_seconds * 100,
  ))
})
const scheduledCount = computed(() => query.data.value?.status.parameters
  .reduce((count, parameter) => count + parameter.scheduled_changes.length, 0) ?? 0)
</script>

<template>
  <main class="page">
    <QueryState :loading="query.loading.value" :error="query.error.value" @retry="query.refresh">
      <template v-if="query.data.value">
        <div class="page-heading">
          <div>
            <span class="eyebrow">Protocol</span>
            <h1>Governance</h1>
            <p>Public proposals, protocol parameters, and control state.</p>
          </div>
          <StatusBadge :value="query.data.value.status.mode" />
        </div>

        <section class="epoch-panel">
          <div class="epoch-heading">
            <div>
              <span class="eyebrow">Current epoch</span>
              <h2>#{{ query.data.value.status.current_epoch_number.toLocaleString() }}</h2>
            </div>
            <strong>{{ remaining > 0 ? `${duration(remaining)} remaining` : 'Awaiting finalized block' }}</strong>
          </div>
          <div class="progress-track" role="progressbar" :aria-valuenow="Math.round(progress)" aria-valuemin="0" aria-valuemax="100">
            <i :style="{ width: `${progress}%` }" />
          </div>
          <div class="epoch-details">
            <div><span>Started</span><b>{{ dateTime(query.data.value.status.current_epoch_started_at) }}</b></div>
            <div><span>Boundary</span><b>{{ dateTime(query.data.value.status.current_epoch_ends_at) }}</b></div>
            <div><span>Mint budget</span><b>{{ query.data.value.status.current_epoch_mint_amount_display }}</b></div>
            <div><span>Immediate reward</span><b>{{ query.data.value.status.current_reward_immediate_bps / 100 }}%</b></div>
            <div><span>Vesting</span><b>{{ duration(query.data.value.status.current_reward_vesting_seconds) }}</b></div>
          </div>
          <p class="epoch-note">The Epoch advances when a finalized block reaches or crosses the boundary.</p>
        </section>

        <section class="summary-strip">
          <div><span>Eligible nodes</span><b>{{ query.data.value.status.governance_eligible_count }}</b></div>
          <div><span>Standard threshold</span><b>{{ query.data.value.status.threshold }}</b></div>
          <div><span>Critical / Node 1 end</span><b>{{ query.data.value.status.critical_threshold }} / {{ query.data.value.status.node1_direct_end_threshold }}</b></div>
          <div><span>Availability</span><b>{{ query.data.value.status.availability_mode }}</b></div>
          <div><span>Emission</span><b>{{ query.data.value.status.emission_paused ? 'Paused' : 'Active' }}</b></div>
        </section>

        <section class="panel parameter-panel">
          <div class="panel-heading">
            <div>
              <span class="eyebrow">Protocol configuration</span>
              <h2>Governance parameters</h2>
            </div>
            <span>{{ query.data.value.status.parameters.length }} parameters · {{ scheduledCount }} scheduled</span>
          </div>
          <div class="table-wrap">
            <table class="parameter-table">
              <thead>
                <tr><th>Parameter</th><th>Category</th><th>Active</th><th>Configured</th><th>Scheduled</th><th>Governance</th></tr>
              </thead>
              <tbody>
                <tr v-for="parameter in query.data.value.status.parameters" :key="parameter.name">
                  <td><code class="parameter-name">{{ parameter.name }}</code></td>
                  <td>{{ parameter.category }}</td>
                  <td><code class="parameter-value">{{ parameter.current_value }}</code></td>
                  <td>
                    <code class="parameter-value">{{ parameter.configured_value }}</code>
                    <small v-if="parameter.current_value !== parameter.configured_value" class="cell-note">next Epoch</small>
                  </td>
                  <td>
                    <div v-if="parameter.scheduled_changes.length" class="scheduled-values">
                      <span v-for="change in parameter.scheduled_changes" :key="change.effective_epoch">
                        <code>{{ change.value }}</code><small>Epoch {{ change.effective_epoch.toLocaleString() }}</small>
                      </span>
                    </div>
                    <span v-else class="muted-value">—</span>
                  </td>
                  <td><span class="governance-tier" :class="{ 'governance-tier--critical': parameter.governance === 'CRITICAL' }">{{ parameter.governance }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="panel-footer parameter-note">Active values reflect the current Epoch snapshot where applicable. Configured values activate at the next Epoch unless an explicit schedule is shown.</div>
        </section>

        <section class="panel">
          <div class="panel-heading"><div><span class="eyebrow">Decisions</span><h2>Proposals</h2></div></div>
          <div v-if="query.data.value.proposals.length" class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Proposal</th><th>Kind</th><th>Proposer</th><th>Created</th><th>Status</th></tr></thead>
              <tbody>
                <tr v-for="proposal in query.data.value.proposals" :key="proposal.proposal_id">
                  <td>#{{ proposal.proposal_id }}</td>
                  <td><RouterLink :to="`/governance/${proposal.proposal_id}`"><b>{{ proposal.title }}</b></RouterLink></td>
                  <td>{{ proposal.kind }}</td>
                  <td><RouterLink :to="`/nodes/${proposal.proposer_node_id}`">Node {{ proposal.proposer_node_id }}</RouterLink></td>
                  <td>{{ relativeTime(proposal.created_at) }}</td>
                  <td><StatusBadge :value="proposal.status" /></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="query-state">No governance proposals yet.</div>
        </section>
      </template>
    </QueryState>
  </main>
</template>
