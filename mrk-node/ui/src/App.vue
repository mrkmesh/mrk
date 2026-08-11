<script setup lang="ts">
import AppHeader from './components/AppHeader.vue'
import { rpc } from './api/rpc'
import { useQuery } from './composables/useQuery'
import type { SystemPing } from './types/rpc'

const system = useQuery(() => rpc<SystemPing>('system.ping'))
</script>

<template><AppHeader /><RouterView /><footer class="app-footer"><span>MRK public ledger</span><span>Node v{{ system.data.value?.node_version ?? '—' }} · Read-only explorer</span></footer></template>
