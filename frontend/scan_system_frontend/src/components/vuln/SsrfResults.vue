<!-- frontend/scan_system_frontend/src/components/vuln/SsrfResults.vue -->
<template>
  <div class="ssrf-results">
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
        label="目标URL"
        width="180"
        show-overflow-tooltip
      ></el-table-column>

      <el-table-column
        label="SSRF类型"
        width="120"
      >
        <template #default="scope">
          <el-tag :type="getSsrfTagType(scope.row)">
            {{ getSsrfTypeName(scope.row) }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column
        label="访问结果"
        width="150"
        show-overflow-tooltip
      >
        <template #default="scope">
          {{ getAccessResult(scope.row) }}
        </template>
      </el-table-column>

      <el-table-column
        label="状态码"
        width="80"
      >
        <template #default="scope">
          {{ getStatusCode(scope.row) }}
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
  name: 'SsrfResults',
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

    // 获取SSRF类型名称
    getSsrfTypeName(row) {
      if (row.vuln_subtype === 'internal_network') {
        return '内网访问';
      } else if (row.vuln_subtype === 'file_protocol') {
        return '文件协议';
      } else if (row.vuln_subtype === 'blind_ssrf') {
        return '盲SSRF';
      } else if (row.vuln_subtype === 'dns_rebinding') {
        return 'DNS重绑定';
      }
      return 'SSRF';
    },

    // 获取SSRF类型对应的标签样式
    getSsrfTagType(row) {
      if (row.vuln_subtype === 'internal_network') {
        return 'danger';
      } else if (row.vuln_subtype === 'file_protocol') {
        return 'warning';
      } else if (row.vuln_subtype === 'blind_ssrf') {
        return 'info';
      } else if (row.vuln_subtype === 'dns_rebinding') {
        return 'warning';
      }
      return 'danger';
    },

    // 获取访问结果
    getAccessResult(row) {
      // 从proof中提取访问结果
      const proof = row.proof || '';
      const resultMatch = proof.match(/访问结果[:：]\s*(.+?)(?=\s*$|\s*[，。,.])/i);
      if (resultMatch && resultMatch[1]) {
        // 截取访问结果前20个字符，如果超过则添加省略号
        const result = resultMatch[1].trim();
        return result.length > 20 ? result.slice(0, 20) + '...' : result;
      }

      // 根据子类型判断默认结果
      if (row.vuln_subtype === 'file_protocol') {
        return '读取到本地文件';
      } else if (row.vuln_subtype === 'internal_network') {
        return '成功访问内网资源';
      } else if (row.vuln_subtype === 'blind_ssrf') {
        return '检测到外部请求';
      }

      return '成功请求';
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
.ssrf-results {
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