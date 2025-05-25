<template>
  <div class="xss-results">
    <el-table
      v-loading="loading"
      :data="vulnResults"
      border
      style="width: 100%"
      :default-sort="{ prop: 'scan_date', order: 'descending' }"
    >
      <el-table-column
        type="index"
        label="序号"
        width="60"
      ></el-table-column>

      <el-table-column
        prop="scan_date"
        label="日期"
        width="150"
        sortable
      >
        <template #default="scope">
          {{ formatDate(scope.row.scan_date) }}
        </template>
      </el-table-column>

      <el-table-column
        prop="asset_host"
        label="资产"
        width="120"
      ></el-table-column>

      <el-table-column
        prop="parameter"
        label="参数"
        width="120"
      ></el-table-column>

      <el-table-column
        prop="payload"
        label="Payload"
        width="150"
        show-overflow-tooltip
      ></el-table-column>

      <!-- 已移除XSS类型列 -->

      <el-table-column
        label="上下文"
        width="120"
        show-overflow-tooltip
      >
        <template #default="scope">
          {{ getXssContext(scope.row) }}
        </template>
      </el-table-column>

      <el-table-column
        prop="url"
        label="URL"
        show-overflow-tooltip
      ></el-table-column>

      <el-table-column
        fixed="right"
        label="操作"
        width="120"
      >
        <template #default="scope">
          <!-- 操作按钮放在同一个div内，保持在同一行 -->
          <div class="operation-buttons">
            <el-button
              @click="$emit('view-detail', scope.row)"
              type="text"
              size="small"
            >
              详情
            </el-button>
            <el-button
              @click="$emit('delete-vuln', scope.row.id)"
              type="text"
              size="small"
              class="delete-btn"
            >
              删除
            </el-button>
          </div>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页 -->
    <div class="pagination" v-if="showPagination">
      <el-pagination
        @size-change="handleSizeChange"
        @current-change="handleCurrentChange"
        :current-page="currentPage"
        :page-sizes="[10, 20, 50, 100]"
        :page-size="pageSize"
        layout="total, sizes, prev, pager, next, jumper"
        :total="total"
      ></el-pagination>
    </div>
  </div>
</template>

<script>
export default {
  name: 'XssResults',
  props: {
    vulnResults: {
      type: Array,
      required: true
    },
    loading: {
      type: Boolean,
      default: false
    },
    currentPage: {
      type: Number,
      default: 1
    },
    pageSize: {
      type: Number,
      default: 10
    },
    total: {
      type: Number,
      default: 0
    },
    showPagination: {
      type: Boolean,
      default: true
    }
  },
  emits: ['size-change', 'current-change', 'view-detail', 'delete-vuln'],
  methods: {
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    },

    // 获取XSS上下文
    getXssContext(row) {
      // 从proof中提取上下文信息
      const proof = row.proof || '';
      const contextMatch = proof.match(/上下文[:：]\s*(\w+)/i);
      if (contextMatch && contextMatch[1]) {
        return contextMatch[1];
      }

      // 如果没有明确的上下文信息，尝试推断
      if (proof.includes('HTML属性')) {
        return 'HTML属性';
      } else if (proof.includes('JavaScript')) {
        return 'JS上下文';
      } else if (proof.includes('HTML标签')) {
        return 'HTML标签';
      }

      return '未知上下文';
    },

    // 分页事件处理
    handleSizeChange(size) {
      this.$emit('size-change', size);
    },
    handleCurrentChange(page) {
      this.$emit('current-change', page);
    }
  }
};
</script>

<style scoped>
.xss-results {
  width: 100%;
}

.pagination {
  margin-top: 20px;
  text-align: right;
}

/* 操作按钮容器样式，确保按钮在同一行 */
.operation-buttons {
  display: flex;
  gap: 5px; /* 控制两个按钮之间的间距 */
  white-space: nowrap;
}

/* 删除按钮样式 */
.delete-btn {
  color: #F56C6C;
}

.delete-btn:hover {
  color: #f78989;
}
</style>