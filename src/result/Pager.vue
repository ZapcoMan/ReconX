<script setup lang="ts">
// 长表分页条：仅在总数超过每页条数时出现；改页大小后把当前页钳回有效范围。
import { computed, watch } from 'vue'

const PAGE_SIZES = [10, 50, 100, 500]

const props = defineProps<{ total: number }>()
const page = defineModel<number>('page', { required: true })
const size = defineModel<number>('size', { required: true })

const visible = computed(() => props.total > size.value)
const lastPage = computed(() => Math.max(1, Math.ceil(props.total / size.value)))

watch(size, () => { if (page.value > lastPage.value) page.value = lastPage.value })
</script>

<template>
  <el-pagination
    v-if="visible"
    class="pager"
    size="small"
    background
    layout="total, sizes, prev, pager, next, jumper"
    :total="props.total"
    :page-sizes="PAGE_SIZES"
    v-model:current-page="page"
    v-model:page-size="size"
  />
</template>

<style scoped>
.pager { display: flex; justify-content: flex-end; margin-top: 8px; }
</style>
