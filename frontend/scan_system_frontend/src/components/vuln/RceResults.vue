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
        label="参数/路径"
        width="120"
      ></el-table-column>

      <el-table-column
        prop="payload"
        label="Payload"
        width="180"
        show-overflow-tooltip
      ></el-table-column>

      <el-table-column
        label="RCE类型"
        width="120"
      >
        <template #default="scope">
          <el-tag :type="getRceTagType(scope.row)">
            {{ getRceTypeName(scope.row) }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column
        label="执行结果"
        width="150"
        show-overflow-tooltip
      >
        <template #default="scope">
          {{ getExecutionResult(scope.row) }}
        </template>
      </el-table-column>

      <el-table-column
        label="验证状态"
        width="100"
      >
        <template #default="scope">
          <el-tag :type="scope.row.is_verified ? 'success' : 'info'" size="small">
            {{ scope.row.is_verified ? '已验证' : '未验证' }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column
        fixed="right"
        label="操作"
        width="120"
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

    // 获取RCE类型名称
    getRceTypeName(row) {
      if (row.vuln_subtype === 'os_command') {
        return '系统命令';
      } else if (row.vuln_subtype === 'blind_os_command') {
        return '盲命令';
      } else if (row.vuln_subtype === 'php_code') {
        return 'PHP代码';
      } else if (row.vuln_subtype === 'java_code') {
        return 'Java代码';
      } else if (row.vuln_subtype === 'python_code') {
        return 'Python代码';
      }
      return '命令注入';
    },

    // 获取RCE类型对应的标签样式
    getRceTagType(row) {
      if (row.vuln_subtype === 'os_command' || row.vuln_subtype === 'php_code') {
        return 'danger';
      } else if (row.vuln_subtype === 'blind_os_command') {
        return 'warning';
      } else if (row.vuln_subtype === 'java_code' || row.vuln_subtype === 'python_code') {
        return 'error';
      }
      return 'danger';
    },

    // 获取执行结果
    getExecutionResult(row) {
      // 从proof中提取执行结果
      const proof = row.proof || '';
      const resultMatch = proof.match(/执行结果[:：]\s*(.+?)(?=\s*$|\s*[，。,.])/i);
      if (resultMatch && resultMatch[1]) {
        // 截取执行结果前20个字符，如果超过则添加省略号
        const result = resultMatch[1].trim();
        return result.length > 20 ? result.slice(0, 20) + '...' : result;
      }

      // 如果没有明确的执行结果
      if (row.vuln_subtype === 'blind_os_command') {
        return '延时响应';
      }

      return '成功执行';
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

.delete-btn {
  color: #F56C6C;
}

.delete-btn:hover {
  color: #f78989;
}
</style>