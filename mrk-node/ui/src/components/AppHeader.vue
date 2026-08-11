<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { rpcState } from '../api/rpc'

const router = useRouter()
const search = ref('')
const open = ref(false)

function submit() {
  const value = search.value.trim()
  if (!value) return
  if (/^\d+$/.test(value)) void router.push(`/blocks/${value}`)
  else if (/^op_/i.test(value)) void router.push(`/operations/${encodeURIComponent(value)}`)
  else if (/^mrk1/i.test(value)) void router.push(`/accounts/${encodeURIComponent(value)}`)
  else if (/^(node:)?\d+$/i.test(value)) void router.push(`/nodes/${value.replace(/^node:/i, '')}`)
  else return
  search.value = ''
  open.value = false
}
</script>

<template>
  <header class="app-header">
    <div class="header-inner">
      <RouterLink class="brand" to="/" aria-label="MRK Explorer home"><span class="brand-mark">M</span><span>MRK <b>Explorer</b></span></RouterLink>
      <button class="menu-button" type="button" aria-label="Toggle navigation" @click="open = !open">Menu</button>
      <nav :class="{ open }" aria-label="Primary navigation">
        <RouterLink to="/blocks">Blocks</RouterLink>
        <RouterLink to="/nodes">Nodes</RouterLink>
        <RouterLink to="/accounts">Accounts</RouterLink>
        <RouterLink to="/governance">Governance</RouterLink>
        <RouterLink to="/treasury">Treasury</RouterLink>
      </nav>
      <form class="search" role="search" @submit.prevent="submit">
        <input v-model="search" aria-label="Search ledger" placeholder="Height, operation, address, node" />
        <button type="submit" aria-label="Search">Search</button>
      </form>
      <span class="connection" :class="rpcState.status"><i />{{ rpcState.status }}</span>
    </div>
  </header>
</template>
