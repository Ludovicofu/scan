<!-- 改进版 SqlInjectionResults.vue -->
<template>
  <div class="sqlinjection-results">
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

      <!-- 匹配值列，使用matched_error字段 -->
      <el-table-column
        label="匹配值"
        width="180"
        show-overflow-tooltip
      >
        <template #default="scope">
          <!-- 针对错误回显型注入显示实际匹配到的SQL错误关键词 -->
          <el-tag
            v-if="isSqlErrorMatch(scope.row)"
            type="danger"
            effect="dark"
          >
            {{ getErrorMatchInfo(scope.row) }}
          </el-tag>
          <!-- 针对时间型注入显示时间延迟 -->
          <el-tag
            v-else-if="isTimeBasedInjection(scope.row)"
            type="warning"
          >
            {{ getResponseTime(scope.row) }}
          </el-tag>
          <span v-else>-</span>
        </template>
      </el-table-column>

      <el-table-column
        label="类型"
        width="100"
      >
        <template #default="scope">
          <el-tag :type="getVulnTagType(scope.row)">
            {{ getVulnTypeName(scope.row) }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column
        label="响应长度"
        width="100"
      >
        <template #default="scope">
          {{ getResponseLength(scope.row) }}
        </template>
      </el-table-column>

      <el-table-column
        label="响应时间"
        width="100"
      >
        <template #default="scope">
          <span v-if="isTimeBasedInjection(scope.row)">{{ getResponseTime(scope.row) }}</span>
          <span v-else>-</span>
        </template>
      </el-table-column>

      <el-table-column
        label="响应码"
        width="80"
      >
        <template #default="scope">
          <span>{{ getStatusCode(scope.row) }}</span>
        </template>
      </el-table-column>

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
  name: 'SqlInjectionResults',
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
  data() {
    return {
      // SQL错误模式
      sqlErrorPatterns: [
        'SQL syntax', 'MySQL', 'ORA-', 'SQLSTATE',
        'Incorrect syntax', 'ODBC Driver', 'PostgreSQL',
        'Warning: mysql', 'Warning: pg', 'SQL Server',
        'invalid query', 'ora_', 'pg_', 'mysqli'
      ]
    };
  },
  methods: {
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    },

    // 是否为错误回显注入
    isSqlErrorMatch(row) {
      return row.vuln_subtype === 'error_based';
    },

    // 是否为基于时间的盲注
    isTimeBasedInjection(row) {
      return row.vuln_subtype === 'blind' && (row.proof || '').includes('时间');
    },

    // 获取错误匹配信息
    getErrorMatchInfo(row) {
      // 优先使用服务端提取的matched_error字段
      if (row.matched_error) {
        return row.matched_error;
      }

      // 如果没有提供matched_error，尝试从proof中提取
      const proof = row.proof || '';

      // 尝试提取"包含SQL错误信息: xxx"格式
      const errorMatch = proof.match(/包含SQL错误信息[：:]?\s*(.+?)(?:\s|$)/);
      if (errorMatch && errorMatch[1]) {
        return errorMatch[1].trim();
      }

      // 如果没有明确提取到错误信息，则尝试从响应中查找常见SQL错误模式
      const response = row.response || '';
      for (const error of this.sqlErrorPatterns) {
        if (response.includes(error)) {
          return error;
        }
      }

      return 'SQL错误';
    },

    // 获取注入类型名称
    getVulnTypeName(row) {
      if (row.vuln_subtype === 'error_based') {
        return '回显型';
      } else if (row.vuln_subtype === 'blind') {
        if ((row.proof || '').includes('时间')) {
          return '时间盲注';
        }
        return '盲注型';
      }
      return '存在';
    },

    // 获取注入类型对应的标签样式
    getVulnTagType(row) {
      if (row.vuln_subtype === 'error_based') {
        return 'danger';
      } else if (row.vuln_subtype === 'blind') {
        return 'warning';
      }
      return 'info';
    },

    // 获取响应时间
    getResponseTime(row) {
      const proof = row.proof || '';
      const timeMatch = proof.match(/响应时间达到\s*(\d+(\.\d+)?)\s*秒/);
      if (timeMatch && timeMatch[1]) {
        return timeMatch[1] + 's';
      }
      return '延时';
    },

    // 获取响应长度
    getResponseLength(row) {
      const response = row.response || '';
      return response.length;
    },

    // 获取状态码
    getStatusCode(row) {
      const response = row.response || '';
      const statusMatch = response.match(/HTTP\/\d\.\d\s+(\d+)/);
      if (statusMatch && statusMatch[1]) {
        return statusMatch[1];
      }
      return '-';
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
.sqlinjection-results {
  width: 100%;
}

.pagination {
  margin-top: 20px;
  text-align: right;
}

.operation-buttons {
  display: flex;
  justify-content: space-around;
}

.delete-btn {
  color: #F56C6C;
}

.delete-btn:hover {
  color: #f78989;
}

/* 定义不同漏洞类型的标签样式 */
:deep(.el-tag--danger.el-tag--dark) {
  background-color: #F56C6C;
  color: white;
  font-weight: bold;
}

:deep(.el-tag--warning) {
  color: #E6A23C;
  border-color: #E6A23C;
}
</style>