<!-- frontend/scan_system_frontend/src/components/vuln/VulnDetailDialog.vue -->
<template>
  <el-dialog
    title="漏洞详情"
    v-model="dialogVisible"
    width="80%"
    destroy-on-close
  >
    <div v-if="vulnResult" class="vuln-detail">
      <!-- 基本信息部分 -->
      <el-descriptions :column="1" border>
        <el-descriptions-item label="资产">{{ vulnResult.asset_host }}</el-descriptions-item>
        <el-descriptions-item label="漏洞类型">
          {{ vulnResult.vuln_type_display }}
          <el-tag v-if="vulnResult.vuln_subtype" style="margin-left: 10px" size="small">
            {{ getVulnSubtypeDisplay(vulnResult.vuln_subtype) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="漏洞名称">{{ vulnResult.name }}</el-descriptions-item>
        <el-descriptions-item label="URL">{{ vulnResult.url }}</el-descriptions-item>
        <el-descriptions-item v-if="vulnResult.parameter" label="参数">{{ vulnResult.parameter }}</el-descriptions-item>
        <el-descriptions-item v-if="vulnResult.payload" label="Payload">{{ vulnResult.payload }}</el-descriptions-item>
        <el-descriptions-item label="描述">{{ vulnResult.description }}</el-descriptions-item>
        <el-descriptions-item label="漏洞证明">{{ vulnResult.proof }}</el-descriptions-item>
        <el-descriptions-item label="扫描日期">{{ formatDate(vulnResult.scan_date) }}</el-descriptions-item>
        <el-descriptions-item label="验证状态">
          <el-tag :type="vulnResult.is_verified ? 'success' : 'info'">
            {{ vulnResult.is_verified ? '已验证' : '未验证' }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <!-- 请求响应详情 -->
      <el-divider content-position="left">请求/响应详情</el-divider>
      <div class="http-details">
        <el-tabs>
          <!-- HTTP请求标签页 - 高亮显示payload -->
          <el-tab-pane label="HTTP请求">
            <div class="detail-panel">
              <div v-if="vulnResult.payload" class="highlight-section">
                <div class="highlight-title">Payload:</div>
                <div class="highlight-content">{{ vulnResult.payload }}</div>
              </div>
              <pre v-html="highlightedRequest"></pre>
            </div>
          </el-tab-pane>

          <!-- HTTP响应标签页 - 高亮显示匹配的错误信息 -->
          <el-tab-pane label="HTTP响应">
            <div class="detail-panel">
              <div v-if="matchedError" class="highlight-section">
                <div class="highlight-title">匹配的SQL错误信息:</div>
                <div class="highlight-content">{{ matchedError }}</div>
              </div>
              <pre v-html="highlightedResponse"></pre>
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="handleClose">关闭</el-button>
        <el-button v-if="vulnResult && !vulnResult.is_verified" type="success" @click="verify">验证</el-button>
      </span>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'VulnDetailDialog',
  props: {
    visible: {
      type: Boolean,
      default: false
    },
    vulnResult: {
      type: Object,
      default: null
    }
  },
  emits: ['close', 'verify'],
  data() {
    return {
      dialogVisible: false
    };
  },
  computed: {
    // 提取匹配到的SQL错误信息
    matchedError() {
      if (!this.vulnResult) return null;
      if (this.vulnResult.vuln_subtype !== 'error_based') return null;

      // 首先尝试从proof中提取
      const proof = this.vulnResult.proof || '';
      const errorMatch = proof.match(/包含SQL错误信息[：:]?\s*(.+?)(?:\s|$)/);
      if (errorMatch && errorMatch[1]) {
        return errorMatch[1].trim();
      }

      // 如果没有从proof中提取到，尝试从响应中查找常见错误关键词
      const response = this.vulnResult.response || '';
      const commonErrors = [
        'SQL syntax', 'MySQL', 'SQLSTATE', 'ORA-',
        'Oracle error', 'Microsoft SQL Server', 'PostgreSQL'
      ];

      for (const error of commonErrors) {
        if (response.includes(error)) {
          return error;
        }
      }

      return null;
    },

    // 高亮显示的请求内容
    highlightedRequest() {
      if (!this.vulnResult || !this.vulnResult.request) return '';

      let request = this.vulnResult.request;
      const payload = this.vulnResult.payload;

      if (payload) {
        // 转义特殊字符
        const escapedPayload = payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        // 高亮替换
        request = request.replace(
          new RegExp(escapedPayload, 'g'),
          '<span class="payload-highlight">$&</span>'
        );
      }

      // 转义HTML字符但保留我们添加的span标签
      return this.escapeHtml(request, ['span']);
    },

    // 高亮显示的响应内容
    highlightedResponse() {
      if (!this.vulnResult || !this.vulnResult.response) return '';

      let response = this.vulnResult.response;

      // 如果有匹配的错误信息，高亮显示
      if (this.matchedError) {
        const escapedError = this.matchedError.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        // 高亮替换
        response = response.replace(
          new RegExp(escapedError, 'g'),
          '<span class="match-highlight">$&</span>'
        );
      }

      // 转义HTML字符但保留我们添加的span标签
      return this.escapeHtml(response, ['span']);
    }
  },
  watch: {
    visible(val) {
      this.dialogVisible = val;
    },
    dialogVisible(val) {
      if (!val) {
        this.$emit('close');
      }
    }
  },
  methods: {
    // 关闭对话框
    handleClose() {
      this.dialogVisible = false;
    },

    // 验证漏洞
    verify() {
      if (this.vulnResult && this.vulnResult.id) {
        this.$emit('verify', this.vulnResult.id);
      }
    },

    // 格式化日期
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    },

    // 获取漏洞子类型显示名称
    getVulnSubtypeDisplay(subtype) {
      const subtypeMap = {
        'error_based': '回显型',
        'blind': '盲注型',
        'time_based': '时间盲注型',
        'boolean_based': '布尔盲注型',
        'stacked_queries': '堆叠查询型',
        'out_of_band': '带外型',
        'stored': '存储型',
        'reflected': '反射型',
        'dom': 'DOM型',
        'lfi': '本地文件包含',
        'rfi': '远程文件包含',
        'os_command': '系统命令',
        'blind_os_command': '盲命令',
        'http_header': 'HTTP头注入'
      };
      return subtypeMap[subtype] || subtype;
    },

    // 转义HTML但保留指定标签
    escapeHtml(text, allowedTags = []) {
      if (!text) return '';

      // 先将允许的标签替换为占位符
      let preserved = text;
      const placeholders = [];

      for (const tag of allowedTags) {
        const regex = new RegExp(`<\\/?${tag}(\\s+[^>]*)?>`,'gi');
        preserved = preserved.replace(regex, (match) => {
          placeholders.push(match);
          return `##PLACEHOLDER_${placeholders.length - 1}##`;
        });
      }

      // 转义所有HTML
      const escaped = preserved
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');

      // 恢复允许的标签
      return escaped.replace(/##PLACEHOLDER_(\d+)##/g, (match, index) => {
        return placeholders[parseInt(index)];
      });
    }
  }
};
</script>

<style scoped>
.vuln-detail {
  font-size: 14px;
}

.highlight-section {
  margin-bottom: 15px;
  background-color: #f5f7fa;
  padding: 10px;
  border-radius: 4px;
  border-left: 4px solid #409EFF;
}

.highlight-title {
  font-weight: bold;
  margin-bottom: 5px;
  color: #303133;
}

.highlight-content {
  font-family: monospace;
  padding: 5px;
  background-color: #ecf5ff;
  border-radius: 3px;
  word-break: break-all;
}

.http-details {
  margin-top: 20px;
}

.detail-panel {
  margin-top: 10px;
}

.detail-panel pre {
  white-space: pre-wrap;
  word-break: break-all;
  background-color: #f5f7fa;
  padding: 10px;
  font-family: monospace;
  font-size: 13px;
  border-radius: 4px;
  max-height: 500px;
  overflow-x: auto;
  overflow-y: auto;
}

:deep(.payload-highlight) {
  background-color: #409EFF;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
}

:deep(.match-highlight) {
  background-color: #F56C6C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
}
</style>