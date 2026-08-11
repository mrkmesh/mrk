<script setup lang="ts">
import { computed } from 'vue'
import { displayEnum } from '../utils/format'

const props = defineProps<{ value: string }>()
const tone = computed(() => {
  const value = props.value.toUpperCase()
  if (['EXIT_PENDING', 'IP_SLOT_UNAVAILABLE', 'REJECTED', 'SUSPENDED', 'ERROR', 'FAILED'].some((item) => value.includes(item))) return 'negative'
  if (['ACTIVE', 'ONLINE', 'READY', 'FINALIZED', 'EXECUTED', 'PASSED'].some((item) => value.includes(item))) return 'positive'
  if (['PENDING', 'WARMING_UP', 'PROBE_STALE', 'UNVERIFIED', 'DEGRADED', 'LITE'].some((item) => value.includes(item))) return 'warning'
  return 'neutral'
})
</script>

<template><span class="badge" :class="`badge--${tone}`"><i />{{ displayEnum(value) }}</span></template>
