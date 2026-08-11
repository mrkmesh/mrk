<script setup lang="ts">
defineProps<{ rows: Array<{ label: string; value: unknown }> }>()
</script>

<template>
  <dl class="detail-grid">
    <template v-for="row in rows" :key="row.label">
      <dt>{{ row.label }}</dt><dd>{{ row.value ?? '—' }}</dd>
    </template>
  </dl>
</template>
