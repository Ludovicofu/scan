<template>
  <el-dialog
    title="扫描结果详情"
    v-model="dialogVisible"
    width="80%"
    @close="handleClose"
  >
    <div v-if="result">
      <el-descriptions :column="1" border>
        <el-descriptions-item label="资产">{{ getAssetDisplay(result) }}</el-descriptions-item>
        <el-descriptions-item label="模块">{{ result.module_display }}</el-descriptions-item>
        <el-descriptions-item label="描述">{{ result.description }}</el-descriptions-item>
        <el-descriptions-item v-if="result.behavior && !isPortScan(result)" label="行为">{{ result.behavior }}</el-descriptions-item>
        <el-descriptions-item v-if="isPortScan(result)" label="行为">端口扫描</el-descriptions-item>
        <el-descriptions-item label="规则类型">{{ result.rule_type }}</el-descriptions-item>
        <el-descriptions-item label="扫描日期">{{ formatDate(result.scan_date) }}</el-descriptions-item>
      </el-descriptions>

      <!-- 端口扫描结果特殊显示 -->
      <div v-if="isPortScan(result)" class="port-scan-results">
        <el-divider content-position="left">端口扫描结果</el-divider>

        <div class="port-scan-wrapper">
          <!-- 端口信息表格 -->
          <el-table
            :data="parsedPortResults"
            border
            stripe
            class="port-scan-table"
          >
            <el-table-column prop="port" label="端口" width="100" />
            <el-table-column prop="banner" label="Banner信息">
              <template #default="scope">
                <div class="banner-content">
                  {{ scope.row.banner }}
                </div>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>
      <!-- 其他类型结果显示 -->
      <div v-else>
        <el-divider content-position="left">匹配值</el-divider>
        <div class="match-value">{{ result.match_value }}</div>
      </div>

      <div class="detail-content">
        <el-divider content-position="left">请求/响应详情</el-divider>
        <el-tabs>
          <el-tab-pane label="请求内容">
            <div class="detail-panel">
              <!-- 使用result中的实际请求数据 -->
              <div v-if="result.behavior && !isPortScan(result)" class="highlight-section">
                <div class="highlight-title">行为路径:</div>
                <div class="highlight-content" v-html="highlightBehavior(result.request_data, result.behavior)"></div>
              </div>
              <pre>{{ result.request_data || '无请求数据' }}</pre>
            </div>
          </el-tab-pane>
          <el-tab-pane label="响应内容">
            <div class="detail-panel">
              <!-- 使用result中的实际响应数据 -->
              <div v-if="result.match_value && !isPortScan(result)" class="highlight-section">
                <div class="highlight-title">匹配值:</div>
                <div class="highlight-content" v-html="highlightMatchValue(result.response_data, result.match_value)"></div>
              </div>
              <pre>{{ result.response_data || '无响应数据' }}</pre>
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="handleClose">关闭</el-button>
      </span>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'InfoResultDetailDialog',
  props: {
    visible: {
      type: Boolean,
      required: true
    },
    result: {
      type: Object,
      default: null
    }
  },
  computed: {
    dialogVisible: {
      get() {
        return this.visible;
      },
      set(value) {
        if (!value) {
          this.$emit('close');
        }
      }
    },
    // 解析端口扫描结果为表格数据
    parsedPortResults() {
      if (!this.result || !this.isPortScan(this.result) || !this.result.match_value) {
        return [];
      }

      let result = [];
      const matchValue = this.result.match_value || '';

      // 处理单行和多行情况
      const lines = matchValue.includes('\n') ? matchValue.split('\n') : [matchValue];

      lines.forEach(line => {
        if (!line || !line.includes(':')) return;

        const [port, ...bannerParts] = line.split(':');
        const banner = bannerParts.join(':').trim();

        result.push({
          port: port.trim(), // 使用JavaScript的trim()方法
          banner: banner || '无Banner信息'
        });
      });

      return result;
    }
  },
  emits: ['close'],
  methods: {
    handleClose() {
      this.$emit('close');
    },

    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    },

    // 获取资产显示文本 - 修改为处理多种情况
    getAssetDisplay(row) {
      if (!row) return '未知资产';

      // 优先级：asset_host > asset（如果asset是字符串） > asset.host > '未知资产'
      if (row.asset_host) {
        return row.asset_host;
      } else if (row.asset) {
        // 如果asset是字符串且不是纯数字ID
        if (typeof row.asset === 'string' && !row.asset.match(/^\d+$/)) {
          return row.asset;
        }
        // 如果asset是对象且有host属性
        else if (typeof row.asset === 'object' && row.asset.host) {
          return row.asset.host;
        }
      }

      return '未知资产';
    },

    // 检查是否为端口扫描结果
    isPortScan(result) {
      return result && (result.rule_type === 'port' || result.is_port_scan);
    },

    // 高亮行为
    highlightBehavior(text, behavior) {
      if (!text || !behavior) return text;

      // 对behavior进行转义，以便正确用于正则表达式
      const escapedBehavior = behavior.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // 创建正则表达式，使用全局搜索和不区分大小写选项
      const regex = new RegExp(escapedBehavior, 'gi');

      // 用带有高亮的HTML替换匹配的文本
      return text.replace(regex, match => `<span class="highlight-behavior">${match}</span>`);
    },

    // 高亮匹配值
    highlightMatchValue(text, matchValue) {
      if (!text || !matchValue) return text;

      // 对matchValue进行转义，以便正确用于正则表达式
      const escapedMatchValue = matchValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // 创建正则表达式，使用全局搜索和不区分大小写选项
      const regex = new RegExp(escapedMatchValue, 'gi');

      // 用带有高亮的HTML替换匹配的文本
      return text.replace(regex, match => `<span class="highlight-match">${match}</span>`);
    }
  }
};
</script>

<style scoped>
.detail-content {
  margin-top: 20px;
}

.detail-panel {
  background-color: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
  margin-top: 10px;
}

.detail-panel pre {
  white-space: pre-wrap;
  word-break: break-all;
  font-family: Consolas, Monaco, 'Andale Mono', monospace;
  font-size: 13px;
  line-height: 1.5;
  margin-top: 10px;
  overflow-x: auto;
  max-height: 500px;
}

.highlight-section {
  margin-bottom: 10px;
  background-color: #ebeef5;
  padding: 10px;
  border-radius: 4px;
}

.highlight-title {
  font-weight: bold;
  margin-bottom: 5px;
}

.highlight-content {
  font-family: Consolas, Monaco, 'Andale Mono', monospace;
  font-size: 13px;
}

:deep(.highlight-behavior) {
  background-color: #67C23A;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
}

:deep(.highlight-match) {
  background-color: #409EFF;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
}

/* 端口扫描结果样式 */
.port-scan-results {
  margin: 20px 0;
}

.port-scan-wrapper {
  margin-top: 15px;
}

.port-scan-table {
  width: 100%;
  margin-bottom: 20px;
}

.banner-content {
  font-family: 'Courier New', monospace;
  word-break: break-all;
}

/* 匹配值样式 */
.match-value {
  background-color: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  font-family: monospace;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>