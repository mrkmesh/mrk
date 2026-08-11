import { onBeforeUnmount, ref, watch, type Ref } from 'vue'

export function useQuery<T>(loader: () => Promise<T>, dependencies: Ref<unknown>[] = []) {
  const data = ref<T | null>(null) as Ref<T | null>
  const error = ref('')
  const loading = ref(true)
  let generation = 0

  async function refresh() {
    const current = ++generation
    loading.value = data.value === null
    error.value = ''
    try {
      const result = await loader()
      if (current === generation) data.value = result
    } catch (reason) {
      if (current === generation) error.value = reason instanceof Error ? reason.message : String(reason)
    } finally {
      if (current === generation) loading.value = false
    }
  }

  if (dependencies.length) watch(dependencies, refresh, { immediate: true })
  else void refresh()
  onBeforeUnmount(() => { generation += 1 })
  return { data, error, loading, refresh }
}
