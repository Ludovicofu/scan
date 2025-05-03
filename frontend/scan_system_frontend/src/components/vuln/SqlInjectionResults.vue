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

      <el-table-column
        label="匹配值"
        width="180"
        show-overflow-tooltip
      >
        <template #default="scope">
          <el-tooltip
            v-if="isSqlErrorMatch(scope.row)"
            :content="getFullErrorMatchInfo(scope.row)"
            placement="top"
            effect="light"
          >
            <span class="match-value error-match">{{ getErrorMatchInfo(scope.row) }}</span>
          </el-tooltip>
          <span v-else class="match-value">{{ scope.row.proof ? getMatchValueFromProof(scope.row.proof) : '无' }}</span>
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

    // 从proof中提取匹配值
    getMatchValueFromProof(proof) {
      if (!proof) return '无';

      // 尝试从证明中提取匹配信息
      const matchInfo = proof.match(/包含SQL错误信息[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i);
      if (matchInfo && matchInfo[1]) {
        return matchInfo[1].trim();
      }

      // 查找其他可能的匹配模式
      const otherPatterns = [
        /匹配[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i,
        /发现[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i,
        /包含[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i
      ];

      for (const pattern of otherPatterns) {
        const match = proof.match(pattern);
        if (match && match[1]) {
          return match[1].trim();
        }
      }

      // 如果没有找到明确的匹配模式，返回前30个字符
      return proof.length > 30 ? proof.slice(0, 30) + '...' : proof;
    },

    // 获取错误匹配信息（用于表格显示）- 修改了字符限制
    getErrorMatchInfo(row) {
      const fullMatchInfo = this.getFullErrorMatchInfo(row);

      // 将字符限制从15增加到30，更好地显示SQL语法错误
      if (fullMatchInfo.length > 30) {
        return fullMatchInfo.slice(0, 30) + '...';
      }

      return fullMatchInfo || '错误匹配';
    },

    // 获取完整的错误匹配信息（用于悬停提示）
    getFullErrorMatchInfo(row) {
      const proof = row.proof || '';

      // 尝试提取SQL错误信息
      const matchInfo = proof.match(/包含SQL错误信息[:：]\s*(.+?)(?=\s*$|\s*[,，。.])/i);
      if (matchInfo && matchInfo[1]) {
        return matchInfo[1].trim();
      }

      // 如果不能从证明中提取，查找常见的SQL错误关键字
      const sqlErrorKeywords = [
        "SQL syntax", "MySQL", "SQL Server", "ORA-", "SQLSTATE",
        "syntax error", "mysqli", "Warning"
      ];

      for (const keyword of sqlErrorKeywords) {
        if (proof.includes(keyword)) {
          // 提取包含关键字的更完整上下文
          const keywordIndex = proof.indexOf(keyword);
          // 扩大上下文范围
          const start = Math.max(0, keywordIndex - 15);
          const end = Math.min(proof.length, keywordIndex + keyword.length + 40);
          return proof.substring(start, end);
        }
      }
      
      return '未能提取完整错误信息';
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

.delete-btn {
  color: #F56C6C;
}

.delete-btn:hover {
  color: #f78989;
}

.match-value {
  word-break: break-all;
  display: inline-block;
  max-width: 100%;
}

.error-match {
  color: #F56C6C;
  font-weight: 500;
  cursor: pointer;
}
</style>