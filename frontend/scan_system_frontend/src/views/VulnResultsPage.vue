<!-- frontend/scan_system_frontend/src/views/VulnResultsPage.vue -->
<template>
  <div class="vuln-results-page">
    <h1>漏洞检测结果</h1>

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

    <!-- 漏洞类型选择 -->
    <div class="vuln-type-tabs">
      <el-tabs v-model="currentVulnType" @tab-click="handleVulnTypeChange">
        <el-tab-pane label="SQL注入" name="sql_injection"></el-tab-pane>
        <el-tab-pane label="XSS" name="xss"></el-tab-pane>
        <el-tab-pane label="文件包含" name="file_inclusion"></el-tab-pane>
        <el-tab-pane label="命令注入" name="command_injection"></el-tab-pane>
        <el-tab-pane label="SSRF" name="ssrf"></el-tab-pane>
        <el-tab-pane label="XXE" name="xxe"></el-tab-pane>
        <el-tab-pane label="其他" name="other"></el-tab-pane>
      </el-tabs>
    </div>

    <!-- 扫描类型切换 -->
    <div class="scan-type-tabs">
      <el-radio-group v-model="currentScanType" @change="handleScanTypeChange">
        <el-radio-button label="passive">被动扫描结果</el-radio-button>
        <el-radio-button label="active">主动扫描结果</el-radio-button>
      </el-radio-group>
    </div>

    <!-- SQL注入结果 -->
    <SqlInjectionResults
      v-if="currentVulnType === 'sql_injection'"
      :vuln-results="filteredResults"
      :loading="loading"
      :current-page="currentPage"
      :page-size="pageSize"
      :total="totalResults"
      :show-pagination="true"
      @size-change="handleSizeChange"
      @current-change="handlePageChange"
      @view-detail="showDetail"
      @delete-vuln="deleteResult"
    />

    <!-- 其他漏洞类型结果 - 通用表格 -->
    <div v-else class="result-table">
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
          width="200"
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
          <el-descriptions-item label="漏洞类型">
            {{ selectedResult.vuln_type_display }}
            <el-tag v-if="selectedResult.vuln_subtype" style="margin-left: 10px" size="small">
              {{ getVulnSubtypeDisplay(selectedResult.vuln_subtype) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="漏洞名称">{{ selectedResult.name }}</el-descriptions-item>
          <el-descriptions-item label="严重程度">
            <el-tag
              :type="getSeverityType(selectedResult.severity)"
              size="small"
            >
              {{ selectedResult.severity_display }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="URL">{{ selectedResult.url }}</el-descriptions-item>
          <el-descriptions-item v-if="selectedResult.parameter" label="参数">{{ selectedResult.parameter }}</el-descriptions-item>
          <el-descriptions-item v-if="selectedResult.payload" label="Payload">{{ selectedResult.payload }}</el-descriptions-item>
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
                <pre>{{ selectedResult.request || '无请求数据' }}</pre>
              </div>
            </el-tab-pane>
            <el-tab-pane label="HTTP响应">
              <div class="detail-panel">
                <!-- 使用实际的响应数据 -->
                <pre>{{ selectedResult.response || '无响应数据' }}</pre>
              </div>
            </el-tab-pane>
            <el-tab-pane label="漏洞详情" v-if="selectedResult.proof">
              <div class="detail-panel">
                <div class="highlight-section">
                  <div class="highlight-title">漏洞证明:</div>
                  <div class="highlight-content">{{ selectedResult.proof }}</div>
                </div>
                <!-- 高亮显示匹配的漏洞内容 -->
                <div v-if="selectedResult.vuln_type === 'sql_injection' && selectedResult.vuln_subtype === 'error_based' && selectedResult.proof && selectedResult.response" class="highlight-section">
                  <div class="highlight-title">响应中的SQL错误:</div>
                  <div class="highlight-content" v-html="highlightSqlError(selectedResult.response, selectedResult.proof)"></div>
                </div>
              </div>
            </el-tab-pane>
            <el-tab-pane label="复现" v-if="selectedResult.vuln_type === 'sql_injection'">
              <div class="detail-panel">
                <div class="highlight-section">
                  <div class="highlight-title">复现方法:</div>
                  <div class="highlight-content">
                    <p>1. 向以下URL发送请求: <code>{{ selectedResult.url }}</code></p>
                    <p v-if="selectedResult.parameter">2. 修改参数 <code>{{ selectedResult.parameter }}</code> 的值为: <code>{{ selectedResult.payload }}</code></p>
                    <p>3. 观察响应中的错误信息或延时情况</p>
                    <p>4. 可使用以下SQL注入工具进行更深入验证:</p>
                    <ul>
                      <li>SQLmap: <code>sqlmap -u "{{ buildSqlmapUrl(selectedResult) }}" --batch</code></li>
                      <li>Burp Suite: 使用Intruder模块进行参数Fuzz测试</li>
                    </ul>
                  </div>
                </div>
              </div>
            </el-tab-pane>
          </el-tabs>
        </div>
      </div>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="detailDialogVisible = false">关闭</el-button>
          <el-button v-if="!selectedResult.is_verified" type="success" @click="verifyVulnerability(selectedResult.id)">验证</el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script>
import ScanProgress from '@/components/common/ScanProgress.vue';
import ResultFilters from '@/components/common/ResultFilters.vue';
import SqlInjectionResults from '@/components/vuln/SqlInjectionResults.vue';
import { vulnScanAPI } from '@/services/api';
import { vulnScanWS } from '@/services/websocket';
import { ElMessage, ElNotification, ElMessageBox } from 'element-plus';

export default {
  name: 'VulnResultsPage',
  components: {
    ScanProgress,
    ResultFilters,
    SqlInjectionResults
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
      currentVulnType: 'sql_injection', // 默认显示SQL注入

      // 详情对话框
      detailDialogVisible: false,
      selectedResult: null,

      // 添加一个Map来跟踪已经显示的结果
      displayedResults: new Map(),
      // 添加一个Set来跟踪已经通知的结果
      notifiedResults: new Set()
    };
  },
  computed: {
    // 根据当前选择的漏洞类型过滤结果
    filteredResults() {
      return this.results.filter(result => result.vuln_type === this.currentVulnType);
    }
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
    this.saveCacheToStorage();
  },
  methods: {
    // 保存和加载去重数据
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
    saveCacheToStorage() {
      try {
        // 将通知过的结果保存到localStorage
        localStorage.setItem('vulnResultNotified', JSON.stringify(Array.from(this.notifiedResults)));
      } catch (e) {
        console.error('保存去重数据失败', e);
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

      console.log("收到新的漏洞扫描结果:", data);

      if (data.data.scan_type === this.currentScanType && data.data.vuln_type === this.currentVulnType) {
        // 检查是否已在显示列表中
        if (!this.displayedResults.has(resultKey)) {
          // 保存到显示集合
          this.displayedResults.set(resultKey, data.data);

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
          page_size: this.pageSize,
          vuln_type: this.currentVulnType
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
        await ElMessageBox.confirm('确认删除此漏洞记录?', '提示', {
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

    // 验证漏洞
    async verifyVulnerability(id) {
      try {
        // 调用验证API
        await vulnScanAPI.verifyVulnerability(id);
        ElMessage.success('漏洞验证成功');

        // 更新详情对话框
        if (this.selectedResult && this.selectedResult.id === id) {
          this.selectedResult.is_verified = true;
        }

        // 刷新结果列表
        await this.fetchResults();
      } catch (error) {
        console.error('漏洞验证失败', error);
        ElMessage.error('漏洞验证失败');
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
    handleVulnTypeChange() {
      this.currentPage = 1; // 重置为第一页
      this.fetchResults();
    },
    handleScanTypeChange() {
      this.currentPage = 1; // 重置为第一页
      this.fetchResults();
    },

    // 获取漏洞严重程度对应的标签类型
    getSeverityType(severity) {
      const severityMap = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
        'info': 'success'
      };
      return severityMap[severity] || 'info';
    },

    // 查看详情
    showDetail(row) {
      this.selectedResult = row;
      this.detailDialogVisible = true;
    },

    // 高亮SQL错误
    highlightSqlError(response, proof) {
      if (!response || !proof) return response;

      // 尝试从证明中提取错误信息关键词
      const errorKeywords = [];

      // 检查常见的SQL错误关键词
      const commonSqlErrors = [
        'SQL syntax', 'MySQL', 'mysqli', 'ORA-', 'Oracle error',
        'SQLSTATE', 'PostgreSQL', 'SQL Server', 'syntax error'
      ];

      commonSqlErrors.forEach(keyword => {
        if (proof.includes(keyword)) {
          errorKeywords.push(keyword);
        }
      });

      // 如果没有找到关键词，尝试提取更多信息
      if (errorKeywords.length === 0) {
        const proofMatch = proof.match(/响应中包含SQL错误信息(.+)/);
        if (proofMatch && proofMatch[1]) {
          errorKeywords.push(proofMatch[1].trim());
        }
      }

      // 如果还是没有关键词，返回原始响应
      if (errorKeywords.length === 0) {
        return response;
      }

      // 高亮显示错误关键词
      let highlightedResponse = response;
      errorKeywords.forEach(keyword => {
        // 转义特殊字符
        const escapedKeyword = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // 创建正则表达式
        const regex = new RegExp(`(${escapedKeyword})`, 'gi');
        // 高亮替换
        highlightedResponse = highlightedResponse.replace(
          regex,
          '<span class="sql-error-highlight">$1</span>'
        );
      });

      return highlightedResponse;
    },

    // 构建SQLmap URL
    buildSqlmapUrl(result) {
      if (!result || !result.url) return '';

      if (result.parameter) {
        // 如果有参数信息，构建带参数的URL
        const urlObj = new URL(result.url);
        if (!urlObj.searchParams.has(result.parameter)) {
          // 如果URL中没有该参数，添加一个占位符
          urlObj.searchParams.set(result.parameter, '*');
        } else {
          // 标记该参数为注入点
          const paramValue = urlObj.searchParams.get(result.parameter);
          urlObj.searchParams.set(result.parameter, paramValue + '*');
        }
        return urlObj.toString();
      }

      // 如果没有参数信息，返回原始URL
      return result.url;
    },

    // 格式化日期
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
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

    // 获取漏洞子类型显示名称
    getVulnSubtypeDisplay(subtype) {
      const subtypeMap = {
        'error_based': '错误回显型',
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

.vuln-type-tabs {
  margin-bottom: 15px;
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

:deep(.sql-error-highlight) {
  background-color: #F56C6C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
}
</style>