<template>
  <div class="rule-section">
    <h3>主动扫描规则</h3>
    <el-table
      v-loading="loading"
      :data="rules"
      border
      style="width: 100%"
    >
      <el-table-column
        type="index"
        label="序号"
        width="60"
      ></el-table-column>

      <el-table-column
        prop="updated_at"
        label="更新时间"
        width="180"
        sortable
      >
        <template #default="scope">
          {{ formatDate(scope.row.updated_at) }}
        </template>
      </el-table-column>

      <el-table-column
        prop="description"
        label="描述"
        width="180"
      ></el-table-column>

      <el-table-column
        prop="behaviors"
        label="行为"
        width="250"
        show-overflow-tooltip
      ></el-table-column>

      <el-table-column
        prop="rule_type_display"
        label="规则类型"
        width="150"
      ></el-table-column>

      <el-table-column
        prop="match_values"
        label="匹配值"
        show-overflow-tooltip
      ></el-table-column>

      <el-table-column
        fixed="right"
        label="操作"
        width="150"
      >
        <template #default="scope">
          <el-button
            @click="$emit('edit-rule', scope.row)"
            type="text"
            size="small"
          >
            修改
          </el-button>
          <el-button
            @click="$emit('delete-rule', scope.row.id)"
            type="text"
            size="small"
            class="delete-btn"
          >
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script>
export default {
  name: 'ActiveScanRules',
  props: {
    rules: {
      type: Array,
      required: true
    },
    loading: {
      type: Boolean,
      default: false
    }
  },
  emits: ['edit-rule', 'delete-rule'],
  methods: {
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    }
  }
};
</script>

<style scoped>
.rule-section {
  margin-bottom: 30px;
}

.rule-section h3 {
  margin-bottom: 15px;
  font-size: 18px;
  color: #303133;
  padding-left: 10px;
  border-left: 4px solid #409EFF;
}

.delete-btn {
  color: #F56C6C;
}

.delete-btn:hover {
  color: #f78989;
}
</style>