<!-- Enhanced VulnResultsPage.vue -->
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

    <!-- SQL注入结果 -->
    <div v-if="currentVulnType === 'sql_injection'" class="result-table">
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

        <!-- 重要修改：显示匹配到的具体SQL错误信息 -->
        <el-table-column
          label="匹配值"
          width="180"
          show-overflow-tooltip
        >
          <template #default="scope">
            <el-tag v-if="scope.row.vuln_subtype === 'error_based'" type="danger">
              {{ getErrorMatchInfo(scope.row) }}
            </el-tag>
            <span v-else-if="isTimeBasedInjection(scope.row)">时间延迟</span>
            <span v-else>-</span>
          </template>
        </el-table-column>

        <el-table-column
          label="类型"
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
            <div class="operation-buttons">
              <el-button @click="showDetail(scope.row)" type="text" size="small">详情</el-button>
              <el-button @click="deleteResult(scope.row.id)" type="text" size="small" class="delete-btn">删除</el-button>
            </div>
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

    <!-- 其他漏洞类型结果 - 通用表格 -->
    <div v-else class="result-table">
      <el-table
        v-loading="loading"
        :data="results"
        border
        style="width: 100%"
      >
        <!-- 其他类型漏洞的表格列... -->
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
          <el-descriptions-item label="资产">{{ selectedResult.asset_host }}</el-descriptions-item>
          <el-descriptions-item label="漏洞类型">
            {{ selectedResult.vuln_type_display }}
            <el-tag v-if="selectedResult.vuln_subtype" style="margin-left: 10px" size="small">
              {{ getVulnSubtypeDisplay(selectedResult.vuln_subtype) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="漏洞名称">{{ selectedResult.name }}</el-descriptions-item>
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

        <!-- 高亮请求和响应 -->
        <el-divider content-position="left">请求/响应详情</el-divider>
        <div class="http-details">
          <el-tabs>
            <!-- HTTP请求标签页 - 高亮显示payload -->
            <el-tab-pane label="HTTP请求">
              <div class="detail-panel">
                <pre v-html="highlightPayloadInRequest(selectedResult)"></pre>
              </div>
            </el-tab-pane>

            <!-- HTTP响应标签页 - 高亮显示匹配的错误信息 -->
            <el-tab-pane label="HTTP响应">
              <div class="detail-panel">
                <pre v-html="highlightMatchInResponse(selectedResult)"></pre>
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
      currentVulnType: 'sql_injection', // 默认显示SQL注入

      // 详情对话框
      detailDialogVisible: false,
      selectedResult: null,

      // 添加一个Map来跟踪已经显示的结果
      displayedResults: new Map(),
      // 添加一个Set来跟踪已经通知的结果
      notifiedResults: new Set(),

      // SQL错误模式
      sqlErrorPatterns: [
        'SQL syntax', 'MySQL', 'ORA-', 'SQLSTATE',
        'Incorrect syntax', 'ODBC Driver', 'PostgreSQL',
        'Warning: mysql', 'Warning: pg', 'SQL Server',
        'invalid query', 'ora_', 'pg_', 'mysqli'
      ]
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
    this.saveCacheToStorage();
  },
  methods: {
    // WebSocket相关方法
    initWebSocket() {
      // 连接WebSocket
      console.log("正在连接WebSocket...");
      vulnScanWS.connect('ws://localhost:8000/ws/vuln_scan/')
        .then(() => {
          console.log("WebSocket连接成功!");

          // 重置缓存，确保不会漏掉新的结果
          vulnScanWS.send({
            type: 'reset_cache'
          });

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

    // 保存和加载去重数据
    loadDeduplicationData() {
      try {
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
        localStorage.setItem('vulnResultNotified', JSON.stringify(Array.from(this.notifiedResults)));
      } catch (e) {
        console.error('保存去重数据失败', e);
      }
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

    // 改进的扫描结果处理方法
    handleScanResult(data) {
      // 创建唯一标识符
      const resultKey = `${data.data.vuln_type}-${data.data.url}-${data.data.parameter || ''}-${data.data.payload || ''}`;

      // 检查是否已经通知过这个结果
      if (this.notifiedResults.has(resultKey)) {
        console.log("忽略重复漏洞结果:", resultKey);
        return;
      }

      // 添加到已通知集合
      this.notifiedResults.add(resultKey);

      console.log("收到新的漏洞扫描结果:", data);

      // 预处理结果数据，特别是对错误回显型SQL注入进行处理
      if (data.data.vuln_type === 'sql_injection' && data.data.vuln_subtype === 'error_based') {
        // 从proof中提取SQL错误信息
        data.data.error_match = this.extractErrorMatchFromProof(data.data.proof);
      }

      // 只按漏洞类型过滤
      if (data.data.vuln_type === this.currentVulnType) {
        // 检查是否已在显示列表中
        if (!this.displayedResults.has(resultKey)) {
          // 保存到显示集合
          this.displayedResults.set(resultKey, data.data);

          // 添加到显示列表
          if (this.results.length < this.pageSize) {
            // 将新结果添加到列表头部
            this.results.unshift(data.data);
            this.totalResults++;
          }

          // 显示通知
          ElNotification({
            title: '漏洞发现',
            message: `发现新漏洞: ${data.data.name}`,
            type: 'warning',
            duration: 5000
          });
        }
      }
    },

    // 提取proof中的错误匹配信息
    extractErrorMatchFromProof(proof) {
      if (!proof) return '';

      // 尝试不同的提取模式
      // 1. 尝试提取"包含SQL错误信息: xxx"格式
      let match = proof.match(/包含SQL错误信息[：:]\s*(.+?)(?:\s|$)/);
      if (match && match[1]) {
        return match[1].trim();
      }

      // 2. 尝试提取"SQL错误信息: xxx"格式
      match = proof.match(/SQL错误信息[：:]\s*(.+?)(?:\s|$)/);
      if (match && match[1]) {
        return match[1].trim();
      }

      // 如果没有找到明确的模式，查找常见SQL错误关键词
      for (const pattern of this.sqlErrorPatterns) {
        if (proof.includes(pattern)) {
          return pattern;
        }
      }

      return '错误回显';
    },

    handleScanStatus(data) {
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
        const params = {
          ...this.filters,
          page: this.currentPage,
          page_size: this.pageSize
        };

        console.log("查询漏洞参数:", params);

        // 使用按类型查询的API
        const response = await vulnScanAPI.getVulnResultsByType(this.currentVulnType, params);

        // 处理查询结果
        this.results = response.results || [];
        this.totalResults = response.count || 0;

        // 为每个SQL注入回显型结果添加错误匹配信息
        this.results.forEach(result => {
          if (result.vuln_type === 'sql_injection' && result.vuln_subtype === 'error_based') {
            result.error_match = this.extractErrorMatchFromProof(result.proof);
          }
        });

        // 更新已显示结果的集合
        this.displayedResults.clear();
        this.results.forEach(result => {
          const resultKey = `${result.vuln_type}-${result.url}-${result.parameter || ''}-${result.payload || ''}`;
          this.displayedResults.set(resultKey, result);
        });

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
          const key = `${resultToRemove.vuln_type}-${resultToRemove.url}-${resultToRemove.parameter || ''}-${resultToRemove.payload || ''}`;
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

    // 获取错误匹配信息
    getErrorMatchInfo(row) {
      // 首先检查是否已提取过错误匹配信息
      if (row.error_match) {
        return row.error_match;
      }

      // 如果没有，则尝试从proof中提取
      if (row.proof) {
        const errorMatch = this.extractErrorMatchFromProof(row.proof);
        return errorMatch || 'SQL错误';
      }

      // 如果没有proof，尝试从response中匹配错误模式
      if (row.response) {
        for (const pattern of this.sqlErrorPatterns) {
          if (row.response.includes(pattern)) {
            return pattern;
          }
        }
      }

      return 'SQL错误';
    },

    // 是否为回显型注入
    isSqlErrorMatch(row) {
      return row.vuln_subtype === 'error_based';
    },

    // 是否为基于时间的盲注
    isTimeBasedInjection(row) {
      return row.vuln_subtype === 'blind' && (row.proof || '').includes('时间');
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

    // 查看详情
    showDetail(row) {
      this.selectedResult = row;
      this.detailDialogVisible = true;
    },

    // 高亮显示请求中的payload
    highlightPayloadInRequest(result) {
      if (!result || !result.request || !result.payload) return result.request;

      const request = result.request;
      const payload = result.payload;

      // 转义特殊字符
      const escapedPayload = payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      try {
        // 高亮替换
        return request.replace(
          new RegExp(escapedPayload, 'g'),
          '<span class="payload-highlight">$&</span>'
        );
      } catch (e) {
        console.error('高亮payload出错', e);
        return request;
      }
    },

    // 高亮显示响应中的匹配值
    highlightMatchInResponse(result) {
      if (!result || !result.response) return result.response;

      let response = result.response;

      // 对于回显型SQL注入，高亮SQL错误信息
      if (result.vuln_subtype === 'error_based') {
        const matchedError = this.getErrorMatchInfo(result);
        if (matchedError && matchedError !== 'SQL错误' && matchedError !== '错误回显') {
          try {
            // 转义特殊字符
            const escapedError = matchedError.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

            // 高亮替换
            response = response.replace(
              new RegExp(escapedError, 'gi'),
              '<span class="match-highlight">$&</span>'
            );
          } catch (e) {
            console.error('高亮匹配值出错', e);
          }
        }
      }

      return response;
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

.result-table {
  margin-top: 20px;
}

.pagination {
  margin-top: 20px;
  text-align: right;
}

.operation-buttons {
  display: flex;
  justify-content: space-around;
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

/* 高亮样式 */
:deep(.payload-highlight) {
  background-color: #409EFF;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

:deep(.match-highlight) {
  background-color: #F56C6C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}
</style>