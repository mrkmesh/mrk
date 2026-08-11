<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import StatusBadge from '../components/StatusBadge.vue'
import DetailGrid from '../components/DetailGrid.vue'
import JsonPanel from '../components/JsonPanel.vue'
import { useQuery } from '../composables/useQuery'
import { dateTime } from '../utils/format'
import type { GovernanceProposal } from '../types/rpc'

interface Tally { yes_power: string | number; no_power: string | number; abstain_power: string | number; validator_yes: number; validator_no: number; validator_total: number }
interface ProposalView { proposal: GovernanceProposal; tally: Tally }
const route = useRoute()
const id = computed(() => Number(route.params.id))
const query = useQuery(() => rpc<ProposalView>('governance.get', { proposal_id: id.value }), [id])
</script>

<template><main class="page"><QueryState :loading="query.loading.value" :error="query.error.value" @retry="query.refresh"><template v-if="query.data.value"><div class="page-heading"><div><span class="eyebrow">Proposal #{{ query.data.value.proposal.proposal_id }}</span><h1>{{ query.data.value.proposal.title }}</h1><p>{{ query.data.value.proposal.kind }}</p></div><StatusBadge :value="query.data.value.proposal.status" /></div>
  <section class="panel detail-panel"><DetailGrid :rows="[{label:'Proposer',value:`Node ${query.data.value.proposal.proposer_node_id}`},{label:'Created',value:dateTime(query.data.value.proposal.created_at)},{label:'Voting ends',value:dateTime(query.data.value.proposal.voting_ends_at)},{label:'Execute after',value:dateTime(query.data.value.proposal.execute_after)}]" /></section>
  <section class="summary-strip"><div><span>Node yes power</span><b>{{ query.data.value.tally.yes_power }}</b></div><div><span>Node no power</span><b>{{ query.data.value.tally.no_power }}</b></div><div><span>Abstain power</span><b>{{ query.data.value.tally.abstain_power }}</b></div><div><span>Validator votes</span><b>{{ query.data.value.tally.validator_yes }} yes / {{ query.data.value.tally.validator_total }}</b></div></section>
  <JsonPanel :value="query.data.value" title="Proposal action and raw data" />
</template></QueryState></main></template>
