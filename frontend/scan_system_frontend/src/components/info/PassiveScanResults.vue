<!-- components/info/PassiveScanResults.vue - 修改后 -->
<template>
  <div class="passive-scan-results">
    <el-table
      v-loading="loading"
      :data="results"
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
        label="资产"
        width="150"
      >
        <template #default="scope">
          <!-- 修改：优先使用asset_host字段，如果没有则尝试使用asset字段 -->
          <span>{{ getAssetDisplay(scope.row) }}</span>
        </template>
      </el-table-column>

      <el-table-column
        prop="module_display"
        label="模块"
        width="120"
      ></el-table-column>

      <el-table-column
        prop="description"
        label="描述"
        width="180"
      ></el-table-column>

      <el-table-column
        prop="rule_type"
        label="规则类型"
        width="120"
      >
        <template #default="scope">
          <!-- 为auto_detect类型添加特殊显示 -->
          <el-tag v-if="scope.row.rule_type === 'auto_detect'" type="success" size="small">自动检测</el-tag>
          <span v-else>{{ scope.row.rule_type }}</span>
        </template>
      </el-table-column>

      <el-table-column
        prop="match_value"
        label="匹配值"
      >
        <template #default="scope">
          <!-- 对端口扫描结果特殊处理，只显示端口号 -->
          <span v-if="scope.row.rule_type === 'port' || scope.row.is_port_scan">
            {{ formatPortNumbers(scope.row.match_value) }}
          </span>
          <span v-else show-overflow-tooltip>{{ scope.row.match_value }}</span>
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
            >详情</el-button>
            <el-button
              @click="$emit('delete-result', scope.row.id)"
              type="text"
              size="small"
              class="delete-btn"
            >删除</el-button>
          </div>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页 -->
    <div class="pagination">
      <el-pagination
        @size-change="$emit('size-change', $event)"
        @current-change="$emit('current-change', $event)"
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
  name: 'PassiveScanResults',
  props: {
    results: {
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
  emits: ['size-change', 'current-change', 'view-detail', 'delete-result'],
  methods: {
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
    },

    // 获取资产显示文本
    getAssetDisplay(row) {
      if (!row) return '未知资产';

      // 优先级：asset_host > asset（如果asset是字符串） > '未知资产'
      if (row.asset_host) {
        return row.asset_host;
      } else if (row.asset && typeof row.asset === 'string' && !row.asset.match(/^\d+$/)) {
        return row.asset;
      } else {
        return '未知资产';
      }
    },

    // 提取端口号
    formatPortNumbers(matchValue) {
      if (!matchValue) return '';

      // 提取所有端口号
      const ports = [];
      const lines = matchValue.split('\n');

      for (const line of lines) {
        if (line && line.includes(':')) {
          const port = line.split(':', 1)[0].trim();
          if (port && !isNaN(port)) {
            ports.push(port);
          }
        }
      }

      // 返回逗号分隔的端口号列表
      return ports.join(', ');
    }
  }
};
</script>

<style scoped>
.passive-scan-results {
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