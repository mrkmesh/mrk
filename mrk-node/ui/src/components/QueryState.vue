<script setup lang="ts">
defineProps<{ loading: boolean; error: string; empty?: boolean }>()
defineEmits<{ retry: [] }>()
</script>

<template>
  <div v-if="loading" class="query-state"><span class="spinner" /> Loading ledger data…</div>
  <div v-else-if="error" class="query-state query-state--error">
    <span>{{ error }}</span><button class="button" type="button" @click="$emit('retry')">Retry</button>
  </div>
  <div v-else-if="empty" class="query-state">No records found.</div>
  <slot v-else />
</template>
