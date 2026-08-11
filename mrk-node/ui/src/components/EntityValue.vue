<script setup lang="ts">
import { ref } from 'vue'
import { short } from '../utils/format'

const props = withDefaults(defineProps<{ value: string; compact?: boolean }>(), { compact: true })
const copied = ref(false)

async function copy() {
  await navigator.clipboard.writeText(props.value)
  copied.value = true
  window.setTimeout(() => { copied.value = false }, 1_200)
}
</script>

<template>
  <span class="entity" :title="value">
    <code>{{ compact ? short(value) : value }}</code>
    <button class="copy" type="button" :aria-label="`Copy ${value}`" @click.stop.prevent="copy">{{ copied ? 'Copied' : 'Copy' }}</button>
  </span>
</template>
