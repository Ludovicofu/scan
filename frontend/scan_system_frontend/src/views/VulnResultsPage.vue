<template>
  <div class="vuln-results-page">
    <h1>漏洞检测结果</h1>

    <div class="placeholder-message">
      <el-alert
        title="功能开发中"
        type="info"
        :closable="false"
        description="漏洞检测模块尚在开发中，敬请期待。"
        show-icon
      ></el-alert>
    </div>

    <!-- 扫描进度 -->
    <ScanProgress
      title="漏洞扫描进度"
      :status="scanStatus"
      :progress="scanProgress"
      :current-url="currentScanUrl"
      :message="scanMessage"
      @start="startScan"
      @stop="stopScan"
    />

    <!-- 过滤器 -->
    <ResultFilters
      type="vuln"
      @filter-change="handleFilterChange"
    />

    <!-- 扫描类型切换 -->
    <div class="scan-type-tabs">
      <el-radio-group v-model="currentScanType" @change="handleScanTypeChange">
        <el-radio-button label="passive">被动扫描结果</el-radio-button>
        <el-radio-button label="active">主动扫描结果</el-radio-button>
      </el-radio-group>
    </div>

    <!-- 结果表格 -->
    <div class="result-table">
      <el-table
        v-loading="loading"
        :data="results"
        border
        style="width: 100%"
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
          prop="vuln_type_display"
          label="漏洞类型"
          width="150"
        ></el-table-column>

        <el-table-column
          prop="name"
          label="漏洞名称"
          width="180"
        ></el-table-column>

        <el-table-column
          prop="severity_display"
          label="严重程度"
          width="100"
        >
          <template #default="scope">
            <el-tag
              :type="getSeverityType(scope.row.severity)"
              size="small"
            >
              {{ scope.row.severity_display }}
            </el-tag>
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
          width="150"
        >
          <template #default="scope">
            <el-button
              @click="showDetail(scope.row)"
              type="text"
              size="small"
            >
              详情
            </el-button>
            <el-button
              @click="deleteResult(scope.row.id)"
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
      <div class="pagination">
        <el-pagination
          @size-change="handleSizeChange"
          @current-change="handlePageChange"
          v-model:current-page="currentPage"
          :page-sizes="[10, 20, 50, 100]"
          v-model:page-size="pageSize"
          layout="total, sizes, prev, pager, next, jumper"
          :total="totalResults"
        ></el-pagination>
      </div>
    </div>

    <!-- 结果详情对话框 -->
    <el-dialog
      title="漏洞详情"
      v-model="detailDialogVisible"
      width="80%"
    >
      <div v-if="selectedResult">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="资产">{{ selectedResult.asset }}</el-descriptions-item>
          <el-descriptions-item label="漏洞名称">{{ selectedResult.name }}</el-descriptions-item>
          <el-descriptions-item label="漏洞类型">{{ selectedResult.vuln_type_display }}</el-descriptions-item>
          <el-descriptions-item label="严重程度">
            <el-tag :type="getSeverityType(selectedResult.severity)">
              {{ selectedResult.severity_display }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="URL">{{ selectedResult.url }}</el-descriptions-item>
          <el-descriptions-item label="描述">{{ selectedResult.description }}</el-descriptions-item>
          <el-descriptions-item label="漏洞证明">{{ selectedResult.proof }}</el-descriptions-item>
          <el-descriptions-item label="扫描日期">{{ formatDate(selectedResult.scan_date) }}</el-descriptions-item>
          <el-descriptions-item label="验证状态">
            <el-tag :type="selectedResult.is_verified ? 'success' : 'info'">
              {{ selectedResult.is_verified ? '已验证' : '未验证' }}
            </el-tag>
          </el-descriptions-item>
        </el-descriptions>

        <el-divider content-position="left">请求详情</el-divider>
        <div class="http-details">
          <el-tabs>
            <el-tab-pane label="HTTP请求">
              <div class="detail-panel">
                <!-- 使用实际的请求数据 -->
                <pre>{{ selectedResult.request_data || '无请求数据' }}</pre>
              </div>
            </el-tab-pane>
            <el-tab-pane label="HTTP响应">
              <div class="detail-panel">
                <!-- 使用实际的响应数据 -->
                <pre>{{ selectedResult.response_data || '无响应数据' }}</pre>
              </div>
            </el-tab-pane>
            <el-tab-pane label="漏洞详情" v-if="selectedResult.proof">
              <div class="detail-panel">
                <div class="highlight-section">
                  <div class="highlight-title">漏洞证明:</div>
                  <div class="highlight-content">{{ selectedResult.proof }}</div>
                </div>
                <!-- 高亮显示匹配的漏洞内容 -->
                <div v-if="selectedResult.proof && selectedResult.response_data" class="highlight-section">
                  <div class="highlight-title">响应中的漏洞点:</div>
                  <div class="highlight-content" v-html="highlightVulnerability(selectedResult.response_data, selectedResult.proof)"></div>
                </div>
              </div>
            </el-tab-pane>
          </el-tabs>
        </div>
      </div>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="detailDialogVisible = false">关闭</el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script>
import ScanProgress from '@/components/common/ScanProgress.vue';
import ResultFilters from '@/components/common/ResultFilters.vue';
import { vulnScanAPI } from '@/services/api';
import { vulnScanWS } from '@/services/websocket';
import { ElMessage, ElNotification, ElMessageBox } from 'element-plus';

export default {
  name: 'VulnResultsPage',
  components: {
    ScanProgress,
    ResultFilters
  },
  data() {
    return {
      // 扫描状态
      scanStatus: 'idle', // idle, scanning, completed, error
      scanProgress: 0,
      currentScanUrl: '',
      scanMessage: '',

      // 表格数据
      loading: false,
      results: [],
      totalResults: 0,
      currentPage: 1,
      pageSize: 10,

      // 过滤条件
      filters: {},
      currentScanType: 'passive',

      // 详情对话框
      detailDialogVisible: false,
      selectedResult: null,

      // 添加一个Map来跟踪已经显示的结果
      displayedResults: new Map(),
      // 添加一个Set来跟踪已经通知的结果
      notifiedResults: new Set()
    };
  },
  created() {
    this.initWebSocket();
    this.fetchResults();

    // 从localStorage恢复去重数据
    this.loadDeduplicationData();
  },
  beforeUnmount() {
    this.closeWebSocket();

    // 保存去重数据到localStorage
    this.saveDeduplicationData();
  },
  methods: {
    // 保存和加载去重数据
    saveDeduplicationData() {
      try {
        // 将通知过的结果保存到localStorage
        localStorage.setItem('vulnResultNotified', JSON.stringify(Array.from(this.notifiedResults)));
      } catch (e) {
        console.error('保存去重数据失败', e);
      }
    },
    loadDeduplicationData() {
      try {
        // 从localStorage加载通知过的结果
        const notifiedData = localStorage.getItem('vulnResultNotified');
        if (notifiedData) {
          this.notifiedResults = new Set(JSON.parse(notifiedData));
        }
      } catch (e) {
        console.error('加载去重数据失败', e);
      }
    },

    // WebSocket相关方法
    initWebSocket() {
      // 连接WebSocket
      console.log("正在连接WebSocket...");
      vulnScanWS.connect('ws://localhost:8000/ws/vuln_scan/')
        .then(() => {
          console.log("WebSocket连接成功!");
          // 添加事件监听器
          vulnScanWS.addListener('scan_progress', this.handleScanProgress);
          vulnScanWS.addListener('scan_result', this.handleScanResult);
          vulnScanWS.addListener('scan_status', this.handleScanStatus);
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          ElMessage.error('连接服务器失败，实时扫描进度将不可用');
        });
    },
    closeWebSocket() {
      // 移除事件监听器
      vulnScanWS.removeListener('scan_progress', this.handleScanProgress);
      vulnScanWS.removeListener('scan_result', this.handleScanResult);
      vulnScanWS.removeListener('scan_status', this.handleScanStatus);
    },
    handleScanProgress(data) {
      // 处理扫描进度更新
      this.scanStatus = data.data.status;
      this.scanProgress = data.data.progress;
      this.currentScanUrl = data.data.url || '';
      this.scanMessage = data.data.message || '';
    },
    // 修改扫描结果处理方法，添加请求和响应数据处理
    handleScanResult(data) {
      // 创建唯一标识符
      const resultKey = `${data.data.vuln_type}-${data.data.name}-${data.data.url}`;

      // 检查是否已经通知过这个结果
      if (this.notifiedResults.has(resultKey)) {
        console.log("忽略重复漏洞结果:", resultKey);
        return;
      }

      // 添加到已通知集合
      this.notifiedResults.add(resultKey);
      // 定期保存去重数据
      this.saveDeduplicationData();

      console.log("收到新的漏洞扫描结果:", data);
      if (data.data.scan_type === this.currentScanType) {
        // 检查是否已在显示列表中
        if (!this.displayedResults.has(resultKey)) {
          // 保存到显示集合，确保包含请求和响应数据
          this.displayedResults.set(resultKey, {
            ...data.data,
            request_data: data.data.request_data || '',
            response_data: data.data.response_data || ''
          });

          // 添加到显示列表
          if (this.results.length < this.pageSize) {
            // 将新结果添加到列表头部
            this.results.unshift(data.data);
            this.totalResults++;
            console.log("添加漏洞到列表");
          }

          // 显示通知，根据严重程度调整通知类型
          const notificationType = this.getSeverityNotificationType(data.data.severity);
          ElNotification({
            title: '漏洞发现',
            message: `发现新漏洞: ${data.data.name} (${data.data.severity_display})`,
            type: notificationType,
            duration: 5000
          });
        }
      }
    },
    handleScanStatus(data) {
      // 处理扫描状态更新
      if (data.status === 'started') {
        this.scanStatus = 'scanning';
        this.scanProgress = 0;
        this.scanMessage = data.message || '扫描已开始';
      } else if (data.status === 'stopped') {
        this.scanStatus = 'idle';
        this.scanProgress = 0;
        this.scanMessage = data.message || '扫描已停止';
      }
    },

    // 扫描操作
    startScan() {
      if (!vulnScanWS.isConnected) {
        ElMessage.error('WebSocket未连接，无法启动扫描');
        return;
      }

      // 发送开始扫描消息
      vulnScanWS.send({
        type: 'start_scan',
        options: {}
      });
    },
    stopScan() {
      if (!vulnScanWS.isConnected) {
        ElMessage.error('WebSocket未连接，无法停止扫描');
        return;
      }

      // 发送停止扫描消息
      vulnScanWS.send({
        type: 'stop_scan'
      });
    },

    // 数据操作方法
    async fetchResults() {
      this.loading = true;
      try {
        let response;
        const params = {
          ...this.filters,
          page: this.currentPage,
          page_size: this.pageSize
        };

        console.log("查询漏洞参数:", params);

        if (this.currentScanType === 'passive') {
          response = await vulnScanAPI.getPassiveScanResults(params);
        } else {
          response = await vulnScanAPI.getActiveScanResults(params);
        }

        console.log("API响应:", response);

        this.results = response.results || [];
        this.totalResults = response.count || 0;

        // 更新已显示结果的集合
        this.displayedResults.clear();
        this.results.forEach(result => {
          const resultKey = `${result.vuln_type}-${result.name}-${result.url}`;
          this.displayedResults.set(resultKey, result);
        });

        console.log("漏洞结果数量:", this.results.length);
      } catch (error) {
        console.error('获取漏洞扫描结果失败', error);
        ElMessage.error('获取漏洞扫描结果失败');
      } finally {
        this.loading = false;
      }
    },

    async deleteResult(id) {
      try {
        await ElMessageBox.confirm('确认删除该漏洞记录?', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        });

        await vulnScanAPI.deleteScanResult(id);
        ElMessage.success('删除成功');

        // 找到并从displayedResults中移除
        const resultToRemove = this.results.find(r => r.id === id);
        if (resultToRemove) {
          const key = `${resultToRemove.vuln_type}-${resultToRemove.name}-${resultToRemove.url}`;
          this.displayedResults.delete(key);
        }

        // 刷新结果列表
        this.fetchResults();
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除漏洞记录失败', error);
          ElMessage.error('删除漏洞记录失败');
        }
      }
    },

    // 分页和过滤器方法
    handleSizeChange(val) {
      this.pageSize = val;
      this.fetchResults();
    },
    handlePageChange(val) {
      this.currentPage = val;
      this.fetchResults();
    },
    handleFilterChange(filters) {
      this.filters = filters;
      this.currentPage = 1; // 重置为第一页
      this.fetchResults();
    },
    handleScanTypeChange() {
      this.currentPage = 1; // 重置为第一页
      this.fetchResults();
    },

    // 查看详情
    showDetail(row) {
      this.selectedResult = row;
      this.detailDialogVisible = true;
    },

    // 高亮显示漏洞点
    highlightVulnerability(text, vulnerabilityProof) {
      if (!text || !vulnerabilityProof) return text;

      // 对vulnerabilityProof进行处理，获取关键词
      let keywords = vulnerabilityProof;

      // 如果是复杂的描述，尝试提取关键词
      if (vulnerabilityProof.length > 30) {
        // 简单处理：提取引号内的内容，或者提取特定的关键字
        const quoteMatch = vulnerabilityProof.match(/'([^']+)'|"([^"]+)"/);
        if (quoteMatch) {
          keywords = quoteMatch[1] || quoteMatch[2];
        } else {
          // 尝试提取关键字（SQL注入、XSS等）
          const keywordMatch = vulnerabilityProof.match(/SQL|XSS|注入|脚本|命令|漏洞|error|syntax|\/bin\/bash|alert\(|<script>|select\s+.*from/i);
          if (keywordMatch) {
            keywords = keywordMatch[0];
          }
        }
      }

      // 对关键词进行转义，以便正确用于正则表达式
      const escapedKeywords = keywords.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // 创建正则表达式，使用全局搜索和不区分大小写选项
      const regex = new RegExp(escapedKeywords, 'gi');

      // 用带有高亮的HTML替换匹配的文本
      return text.replace(regex, match => `<span class="highlight-vulnerability">${match}</span>`);
    },

    // 工具方法
    getSeverityType(severity) {
      const severityMap = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
        'info': 'success'
      };
      return severityMap[severity] || 'info';
    },

    getSeverityNotificationType(severity) {
      const notificationMap = {
        'high': 'error',
        'medium': 'warning',
        'low': 'info',
        'info': 'success'
      };
      return notificationMap[severity] || 'info';
    },

    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    }
  }
};
</script>

<style scoped>
.vuln-results-page {
  padding: 20px;
}

h1 {
  margin-bottom: 20px;
  font-size: 24px;
  color: #303133;
}

.placeholder-message {
  margin-bottom: 20px;
}

.scan-type-tabs {
  margin-bottom: 20px;
}

.result-table {
  margin-top: 20px;
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

.http-details {
  margin-top: 15px;
}

.detail-panel {
  background-color: #f5f7fa;
  padding: 10px;
  border-radius: 4px;
  margin-top: 10px;
}

.detail-panel pre {
  white-space: pre-wrap;
  word-wrap: break-word;
  background-color: #f5f7fa;
  padding: 10px;
  font-family: monospace;
  font-size: 13px;
  border-radius: 4px;
  max-height: 500px;
  overflow-x: auto;
  overflow-y: auto;
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

:deep(.highlight-vulnerability) {
  background-color: #F56C6C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
}
</style>