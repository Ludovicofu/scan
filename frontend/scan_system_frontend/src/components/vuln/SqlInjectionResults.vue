<!-- frontend/scan_system_frontend/src/components/vuln/SqlInjectionResults.vue -->
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
        width="180"
        sortable
      >
        <template #default="scope">
          {{ formatDate(scope.row.scan_date) }}
        </template>
      </el-table-column>

      <el-table-column
        prop="asset"
        label="资产"
        width="150"
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

      <el-table-column
        label="匹配值"
        width="120"
        show-overflow-tooltip
      >
        <template #default="scope">
          <span v-if="isSqlErrorMatch(scope.row)">{{ getErrorMatchInfo(scope.row) }}</span>
          <span v-else>无</span>
        </template>
      </el-table-column>

      <el-table-column
        label="差异"
        width="100"
      >
        <template #default="scope">
          <el-tag :type="getVulnTagType(scope.row)">
            {{ getVulnTypeName(scope.row) }}
          </el-tag>
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
        label="状态码"
        width="80"
      >
        <template #default="scope">
          <span>{{ getStatusCode(scope.row) }}</span>
        </template>
      </el-table-column>

      <el-table-column
        fixed="right"
        label="操作"
        width="150"
      >
        <template #default="scope">
          <el-button
            @click="$emit('view-detail', scope.row)"
            type="primary"
            plain
            size="small"
          >
            详情
          </el-button>
          <el-button
            @click="$emit('delete-vuln', scope.row.id)"
            type="danger"
            plain
            size="small"
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
      // 从proof中提取匹配信息，截取前15个字符
      const proof = row.proof || '';
      const matchInfo = proof.match(/包含SQL错误信息(.*)/);
      if (matchInfo && matchInfo[1]) {
        return matchInfo[1].slice(0, 15) + '...';
      }
      return '错误匹配';
    },

    // 获取注入类型名称
    getVulnTypeName(row) {
      if (row.vuln_subtype === 'error_based') {
        return '错误回显';
      } else if (row.vuln_subtype === 'blind') {
        if ((row.proof || '').includes('时间')) {
          return '时间盲注';
        }
        return '盲注';
      }
      return '注入';
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
</style>