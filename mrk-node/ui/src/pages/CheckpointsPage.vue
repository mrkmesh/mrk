<script setup lang="ts">
import { rpc } from '../api/rpc'
import EntityValue from '../components/EntityValue.vue'
import QueryState from '../components/QueryState.vue'
import { useQuery } from '../composables/useQuery'
import { dateTime, relativeTime } from '../utils/format'
import type { BootstrapCheckpoint } from '../types/rpc'

const query = useQuery(() => rpc<BootstrapCheckpoint[]>('chain.checkpoints'))
</script>

<template>
  <main class="page">
    <div class="page-heading">
      <div>
        <span class="eyebrow">Ledger</span>
        <h1>Checkpoints</h1>
        <p>Bootstrap checkpoints currently retained by this node.</p>
      </div>
      <button class="button" type="button" :disabled="query.loading.value" @click="query.refresh">Refresh</button>
    </div>

    <div class="notice">
      <b>Verify independently</b>
      A checkpoint root reported by this node is not a trust source. Compare it with an independent release or multiple operators before bootstrapping.
    </div>

    <section class="panel">
      <QueryState
        :loading="query.loading.value"
        :error="query.error.value"
        :empty="!query.data.value?.length"
        @retry="query.refresh"
      >
        <div class="table-wrap">
          <table>
            <thead><tr><th>Height</th><th>Finalized</th><th>Age</th><th>State root</th></tr></thead>
            <tbody>
              <tr v-for="checkpoint in query.data.value" :key="checkpoint.height">
                <td>{{ checkpoint.height.toLocaleString() }}</td>
                <td>{{ dateTime(checkpoint.finalized_at) }}</td>
                <td>{{ relativeTime(checkpoint.finalized_at) }}</td>
                <td><EntityValue :value="checkpoint.state_root" /></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="panel-footer">Newest retained checkpoint first</div>
      </QueryState>
    </section>
  </main>
</template>
