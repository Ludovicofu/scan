<!-- frontend/scan_system_frontend/src/components/vuln/GeneralVulnResults.vue -->
<template>
  <div class="general-vuln-results">
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
        width="180"
        sortable
      >
        <template #default="scope">
          {{ formatDate(scope.row.scan_date) }}
        </template>
      </el-table-column>

      <el-table-column
        prop="asset_host"
        label="资产"
        width="150"
      ></el-table-column>

      <el-table-column
        prop="name"
        label="漏洞名称"
        width="200"
      ></el-table-column>

      <el-table-column
        label="严重程度"
        width="100"
      >
        <template #default="scope">
          <el-tag :type="getSeverityType(scope.row.severity)">
            {{ scope.row.severity_display }}
          </el-tag>
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
        width="150"
      >
        <template #default="scope">
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
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页 -->
    <div class="pagination">
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
  name: 'GeneralVulnResults',
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
    }
  },
  emits: ['size-change', 'current-change', 'view-detail', 'delete-vuln'],
  methods: {
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    },

    // 获取严重程度对应的标签类型
    getSeverityType(severity) {
      const severityMap = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
        'info': 'success'
      };
      return severityMap[severity] || 'info';
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
.general-vuln-results {
  width: 100%;
}

.pagination {
  margin-top: 20px;
  text-align: right;
}

.delete-btn {
  color: #F56C6C;
}

.delete-btn:hover {
  color: #f78989;
}
</style>