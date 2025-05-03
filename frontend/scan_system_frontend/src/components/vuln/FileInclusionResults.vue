<!-- frontend/scan_system_frontend/src/components/vuln/FileInclusionResults.vue -->
<template>
  <div class="fileinclusion-results">
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
        label="文件类型"
        width="120"
      >
        <template #default="scope">
          <el-tag :type="getInclusionTagType(scope.row)">
            {{ getInclusionTypeName(scope.row) }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column
        label="匹配内容"
        width="180"
        show-overflow-tooltip
      >
        <template #default="scope">
          {{ getMatchContent(scope.row) }}
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
  name: 'FileInclusionResults',
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

    // 获取文件包含类型名称
    getInclusionTypeName(row) {
      if (row.vuln_subtype === 'lfi') {
        return '本地文件';
      } else if (row.vuln_subtype === 'rfi') {
        return '远程文件';
      }
      return '文件包含';
    },

    // 获取文件包含类型对应的标签样式
    getInclusionTagType(row) {
      if (row.vuln_subtype === 'lfi') {
        return 'danger';
      } else if (row.vuln_subtype === 'rfi') {
        return 'warning';
      }
      return 'info';
    },

    // 获取匹配的文件内容
    getMatchContent(row) {
      // 从proof中提取匹配的文件内容
      const proof = row.proof || '';

      if (row.vuln_subtype === 'lfi') {
        // 尝试从LFI证明中提取特征
        const matchContent = proof.match(/特征[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i);
        if (matchContent && matchContent[1]) {
          return matchContent[1].trim();
        }
      } else if (row.vuln_subtype === 'rfi') {
        // 尝试从RFI证明中提取特征
        const matchContent = proof.match(/特征[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i);
        if (matchContent && matchContent[1]) {
          return matchContent[1].trim();
        }
      }

      // 如果没有明确的匹配内容，尝试提取其他有用信息
      const fileTypeMatch = proof.match(/包含\s+(.+?)\s+文件/i);
      if (fileTypeMatch && fileTypeMatch[1]) {
        return `${fileTypeMatch[1]}文件内容`;
      }

      return '无匹配内容';
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
.fileinclusion-results {
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