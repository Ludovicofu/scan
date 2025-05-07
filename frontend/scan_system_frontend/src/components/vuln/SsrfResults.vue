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
          <el-tooltip
            :content="getSsrfTypeDescription(scope.row)"
            placement="top"
            effect="light"
          >
            <el-tag :type="getSsrfTagType(scope.row)">
              {{ getSsrfTypeName(scope.row) }}
              <i class="el-icon-info" style="margin-left: 3px;"></i>
            </el-tag>
          </el-tooltip>
        </template>
      </el-table-column>

      <el-table-column
        label="匹配特征"
        width="200"
        show-overflow-tooltip
      >
        <template #default="scope">
          <span class="matched-feature">{{ getMatchedFeature(scope.row) }}</span>
        </template>
      </el-table-column>

      <el-table-column
        label="检测详情"
        width="200"
      >
        <template #default="scope">
          <div v-if="getAccessDetail(scope.row)">
            <el-tooltip
              :content="getAccessDetail(scope.row)"
              placement="top"
              effect="light"
            >
              <span class="access-detail">{{ getAccessDetail(scope.row, true) }}</span>
            </el-tooltip>
          </div>
          <span v-else class="no-detail">无详细信息</span>
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

    // 获取SSRF类型的详细说明
    getSsrfTypeDescription(row) {
      const descriptions = {
        'internal_network': '内网访问型SSRF允许攻击者访问内部网络资源，如内部服务器、数据库等，可能导致内网信息泄露或横向移动攻击。',
        'file_protocol': '文件协议型SSRF允许攻击者读取服务器本地文件，可能导致敏感配置文件、密码文件等信息泄露。',
        'blind_ssrf': '盲SSRF是指攻击者无法直接看到响应内容，但可以通过时间延迟或外部回连等方式确认漏洞存在。',
        'dns_rebinding': 'DNS重绑定型SSRF通过DNS响应变化绕过同源策略限制，实现对内部资源的访问。',
        'general_ssrf': '通用SSRF漏洞允许服务器访问攻击者控制的资源，可能导致信息泄露、内网探测或服务器资源消耗。'
      };

      const subtype = row.vuln_subtype || 'general_ssrf';
      return descriptions[subtype] || descriptions['general_ssrf'];
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

    // 获取匹配到的特征
    getMatchedFeature(row) {
      // 从proof中提取匹配特征
      const proof = row.proof || '';
      const featureMatch = proof.match(/响应中包含匹配特征:\s*(.+?)(?=，|$)/i);

      if (featureMatch && featureMatch[1]) {
        const feature = featureMatch[1].trim();
        // 截取特征前30个字符，如果超过则添加省略号
        return feature.length > 30 ? feature.slice(0, 30) + '...' : feature;
      }

      // 如果没有提取到特征，尝试其他方法
      if (row.vuln_subtype === 'file_protocol') {
        return '文件内容特征匹配';
      } else if (row.vuln_subtype === 'internal_network') {
        return '内网服务响应特征';
      }

      return '响应特征匹配';
    },

    // 获取访问详情
    getAccessDetail(row, truncate = false) {
      // 从proof中提取访问结果
      const proof = row.proof || '';
      const accessMatch = proof.match(/访问结果:\s*(.+?)(?=，|$)/i);

      if (accessMatch && accessMatch[1]) {
        const result = accessMatch[1].trim();
        // 如果需要截断，截取前20个字符
        if (truncate && result.length > 20) {
          return result.slice(0, 20) + '...';
        }
        return result;
      }

      // 根据子类型判断默认结果
      if (row.vuln_subtype === 'file_protocol') {
        return '成功读取文件内容';
      } else if (row.vuln_subtype === 'internal_network') {
        return '成功访问内网资源';
      } else if (row.vuln_subtype === 'blind_ssrf') {
        return '外部服务器收到请求';
      }

      return '请求成功且匹配特征';
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

.matched-feature {
  color: #E6A23C;
  font-weight: bold;
}

.access-detail {
  color: #409EFF;
}

.no-detail {
  color: #909399;
  font-style: italic;
}
</style>