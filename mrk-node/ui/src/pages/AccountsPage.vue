<script setup lang="ts">
import { ref } from 'vue'
import { rpc } from '../api/rpc'
import QueryState from '../components/QueryState.vue'
import EntityValue from '../components/EntityValue.vue'
import { useQuery } from '../composables/useQuery'
import type { AccountRankingList } from '../types/rpc'

const accounts = ref<AccountRankingList['accounts']>([])
const cursor = ref<string | null>(null)
const query = useQuery(async () => {
  const page = await rpc<AccountRankingList>('account.list', { limit: 50 })
  accounts.value = page.accounts
  cursor.value = page.next_cursor
  return page
})
const loadingMore = ref(false)

function percentage(bps: number): string {
  return `${(bps / 100).toFixed(2)}%`
}

async function loadMore() {
  if (cursor.value === null) return
  loadingMore.value = true
  try {
    const page = await rpc<AccountRankingList>('account.list', { cursor: cursor.value, limit: 50 })
    accounts.value.push(...page.accounts)
    cursor.value = page.next_cursor
  } catch {
    await query.refresh()
  } finally {
    loadingMore.value = false
  }
}
</script>

<template>
  <main class="page">
    <div class="page-heading">
      <div><span class="eyebrow">Ledger</span><h1>Accounts</h1><p>Funded accounts ranked by the previous Epoch's final balance.</p></div>
    </div>
    <QueryState :loading="query.loading.value" :error="query.error.value" :empty="!accounts.length" @retry="query.refresh">
      <template v-if="query.data.value">
        <section class="summary-strip summary-strip--three">
          <div><span>Funded accounts</span><b>{{ query.data.value.funded_account_count.toLocaleString() }}</b></div>
          <div><span>Total account balance</span><b>{{ query.data.value.total_account_balance_display }}</b></div>
          <div><span>Ranking snapshot</span><b>Epoch {{ query.data.value.snapshot_epoch.toLocaleString() }}</b><small>Height {{ query.data.value.snapshot_height.toLocaleString() }}</small></div>
        </section>
        <section class="panel">
          <div class="table-wrap">
            <table>
              <thead><tr><th>Rank</th><th>Address</th><th>Balance</th><th>Share</th></tr></thead>
              <tbody>
                <tr v-for="account in accounts" :key="account.address">
                  <td>#{{ account.rank.toLocaleString() }}</td>
                  <td><RouterLink :to="`/accounts/${account.address}`"><EntityValue :value="account.address" /></RouterLink></td>
                  <td><b>{{ account.balance_display }}</b></td>
                  <td>{{ percentage(account.balance_share_bps) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="panel-footer"><button v-if="cursor !== null" class="button" type="button" :disabled="loadingMore" @click="loadMore">{{ loadingMore ? 'Loading…' : 'Load more accounts' }}</button><span v-else>End of funded accounts</span></div>
        </section>
      </template>
    </QueryState>
  </main>
</template>
