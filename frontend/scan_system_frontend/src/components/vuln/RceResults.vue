<!-- frontend/scan_system_frontend/src/components/vuln/RceResults.vue -->
<template>
  <div class="rce-results">
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
        width="180"
        show-overflow-tooltip
      ></el-table-column>

      <el-table-column
        label="漏洞类型"
        width="120"
      >
        <template #default="scope">
          <el-tag type="danger">{{ getVulnSubtypeDisplay(scope.row.vuln_subtype) }}</el-tag>
        </template>
      </el-table-column>

      <el-table-column
        label="匹配值"
        width="180"
        show-overflow-tooltip
      >
        <template #default="scope">
          {{ getMatchValue(scope.row) }}
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
  name: 'RceResults',
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

    // 获取漏洞子类型显示名称
    getVulnSubtypeDisplay(subtype) {
      const subtypeMap = {
        'os_command': '命令执行',
        'blind_os_command': '盲命令执行',
        'php_code': 'PHP代码执行',
        'java_code': 'Java代码执行',
        'python_code': 'Python代码执行',
        'js_code': 'JS代码执行'
      };

      // 如果没有子类型，默认显示为"命令执行"
      if (!subtype) return '命令执行';

      return subtypeMap[subtype] || subtype;
    },

    // 获取匹配值
    getMatchValue(row) {
      // 从proof中提取执行结果
      const proof = row.proof || '';

      // 尝试多种模式匹配执行结果
      const patterns = [
        /执行结果[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i,
        /结果[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i,
        /输出[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i,
        /回显[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i
      ];

      for (const pattern of patterns) {
        const match = proof.match(pattern);
        if (match && match[1]) {
          const result = match[1].trim();
          return result.length > 30 ? result.slice(0, 30) + '...' : result;
        }
      }

      // 如果没有明确的执行结果，返回 echo rce_test_cmd 这个默认值
      return 'echo rce_test_cmd';
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
.rce-results {
  width: 100%;
}

.pagination {
  margin-top: 20px;
  text-align: right;
}

.operation-buttons {
  display: flex;
  gap: 5px;
  white-space: nowrap;
}

.delete-btn {
  color: #F56C6C;
}

.delete-btn:hover {
  color: #f78989;
}
</style>