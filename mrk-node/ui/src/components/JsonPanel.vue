<script setup lang="ts">
defineProps<{ value: unknown; title?: string }>()
</script>

<template>
  <details class="json-panel"><summary>{{ title ?? 'Raw JSON' }}</summary><pre>{{ JSON.stringify(value, null, 2) }}</pre></details>
</template>
