<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, useId } from 'vue'
import type { CSSProperties } from 'vue'

defineProps<{ label: string; detail?: string }>()

const tooltipId = useId()
const trigger = ref<HTMLElement | null>(null)
const bubble = ref<HTMLElement | null>(null)
const open = ref(false)
const positionStyle = ref<CSSProperties>({ visibility: 'hidden' })

function position() {
  if (!open.value || !trigger.value || !bubble.value) return
  const anchor = trigger.value.getBoundingClientRect()
  const tip = bubble.value.getBoundingClientRect()
  const gap = 8
  const edge = 8
  let top = anchor.top - tip.height - gap
  if (top < edge) top = anchor.bottom + gap
  const left = Math.min(
    window.innerWidth - tip.width - edge,
    Math.max(edge, anchor.left + (anchor.width - tip.width) / 2),
  )
  positionStyle.value = { top: `${Math.round(top)}px`, left: `${Math.round(left)}px` }
}

function show() {
  if (open.value) return
  open.value = true
  positionStyle.value = { visibility: 'hidden' }
  window.addEventListener('resize', position)
  window.addEventListener('scroll', position, true)
  void nextTick(position)
}

function hide() {
  open.value = false
  window.removeEventListener('resize', position)
  window.removeEventListener('scroll', position, true)
}

onBeforeUnmount(hide)
</script>

<template>
  <span
    ref="trigger"
    class="tooltip-trigger"
    tabindex="0"
    :aria-describedby="open ? tooltipId : undefined"
    @mouseenter="show"
    @mouseleave="hide"
    @focus="show"
    @blur="hide"
    @keydown.esc="hide"
  >
    <slot />
  </span>
  <Teleport to="body">
    <span v-if="open" :id="tooltipId" ref="bubble" class="tooltip-bubble" role="tooltip" :style="positionStyle">
      <strong>{{ label }}</strong>
      <small v-if="detail">{{ detail }}</small>
    </span>
  </Teleport>
</template>
