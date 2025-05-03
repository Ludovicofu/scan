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

        <el-table-column
          label="匹配值"
          width="120"
          show-overflow-tooltip
        >
          <template #default="scope">
            <span v-if="isSqlErrorMatch(scope.row)">{{ getErrorMatchInfo(scope.row) }}</span>
            <span v-else>无</span>
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
          prop="asset_host"
          label="资产"
          width="150"
        ></el-table-column>

        <el-table-column
          prop="name"
          label="漏洞名称"
          width="200"
        ></el-table-column>

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

        <el-divider content-position="left">请求/响应详情</el-divider>
        <div class="http-details">
          <el-tabs>
            <el-tab-pane label="HTTP请求">
              <div class="detail-panel">
                <!-- 显示完整的请求数据，使用pre标签保留格式 -->
                <pre class="http-content">{{ formatHttpRequest(selectedResult.request) }}</pre>

                <!-- 如果有参数和载荷，高亮显示 -->
                <div v-if="selectedResult.parameter && selectedResult.payload" class="highlight-section">
                  <div class="highlight-title">注入点:</div>
                  <div class="highlight-content">
                    参数 <span class="param-highlight">{{ selectedResult.parameter }}</span>
                    载荷 <span class="payload-highlight">{{ selectedResult.payload }}</span>
                  </div>
                </div>
              </div>
            </el-tab-pane>
            <el-tab-pane label="HTTP响应">
              <div class="detail-panel">
                <!-- 使用v-html显示带有高亮效果的响应内容 -->
                <div v-html="highlightSqlError(selectedResult.response, selectedResult.proof)"></div>
              </div>
            </el-tab-pane>
            <el-tab-pane label="漏洞详情" v-if="selectedResult.proof">
              <div class="detail-panel">
                <div class="highlight-section">
                  <div class="highlight-title">漏洞证明:</div>
                  <div class="highlight-content">{{ selectedResult.proof }}</div>
                </div>

                <!-- 漏洞类型特定信息 -->
                <div v-if="selectedResult.vuln_type === 'sql_injection'" class="injection-details">
                  <h4>SQL注入类型: {{ getVulnSubtypeDisplay(selectedResult.vuln_subtype) }}</h4>
                  <div v-if="selectedResult.vuln_subtype === 'error_based'">
                    <p>回显型SQL注入漏洞是指攻击者可以通过输入特定的SQL语句片段，使应用程序产生SQL错误并在响应中显示错误信息，从而泄露数据库结构或其他敏感信息。</p>
                  </div>
                  <div v-else-if="selectedResult.vuln_subtype === 'blind'">
                    <p>盲注型SQL注入漏洞是指攻击者无法直接看到SQL错误信息，但可以通过观察应用程序的行为变化（如响应时间）来推断SQL语句的执行结果。</p>
                  </div>
                </div>
              </div>
            </el-tab-pane>
            <el-tab-pane label="复现" v-if="selectedResult.vuln_type === 'sql_injection'">
              <div class="detail-panel">
                <div class="highlight-section">
                  <div class="highlight-title">复现方法:</div>
                  <div class="highlight-content">
                    <p>1. 向以下URL发送请求: <code>{{ selectedResult.url }}</code></p>
                    <p v-if="selectedResult.parameter">2. 修改参数 <code>{{ selectedResult.parameter }}</code> 的值为: <code class="payload-highlight">{{ selectedResult.payload }}</code></p>
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
            console.log("添加漏洞到列表");
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
        const params = {
          ...this.filters,
          page: this.currentPage,
          page_size: this.pageSize
        };

        console.log("查询漏洞参数:", params);

        // 使用按类型查询的API
        const response = await vulnScanAPI.getVulnResultsByType(this.currentVulnType, params);

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

    // 查看详情
    showDetail(row) {
      this.selectedResult = row;
      this.detailDialogVisible = true;
    },

    // 格式化HTTP请求
    formatHttpRequest(request) {
      if (!request) return '无请求数据';

      // 如果请求不是以HTTP开头，尝试添加前缀
      if (!request.startsWith('GET') && !request.startsWith('POST') && !request.startsWith('HTTP')) {
        // 推测并补充HTTP方法
        const url = this.selectedResult ? this.selectedResult.url : '';
        const method = url.includes('?') ? 'GET' : 'POST';
        return `${method} ${url} HTTP/1.1\nHost: ${new URL(url).hostname}\n\n${request}`;
      }

      return request;
    },

    // 格式化HTTP响应
    formatHttpResponse(response) {
      if (!response) return '无响应数据';

      // 如果响应不是以HTTP开头，尝试添加前缀
      if (!response.startsWith('HTTP')) {
        return `HTTP/1.1 200 OK\n\n${response}`;
      }

      return response;
    },

    // 高亮SQL错误信息
    highlightSqlError(response, proof) {
      if (!response || !proof) return '<pre class="http-content">无响应数据</pre>';

      let responseText = this.formatHttpResponse(response);
      // 先将HTML特殊字符转义，防止XSS攻击
      responseText = this.escapeHtml(responseText);

      // 从证明中提取错误关键词
      const errorKeywords = this.extractErrorKeywords(proof);

      // 如果没有关键词，返回原始响应
      if (errorKeywords.length === 0) {
        return `<pre class="http-content">${responseText}</pre>`;
      }

      // 高亮显示错误关键词
      for (const keyword of errorKeywords) {
        if (keyword.length < 3) continue; // 跳过太短的关键词

        try {
          // 创建一个忽略大小写的正则表达式
          const regex = new RegExp(`(${this.escapeRegExp(keyword)})`, 'gi');

          // 替换为高亮的HTML
          responseText = responseText.replace(
            regex,
            '<span class="sql-error-highlight">$1</span>'
          );
        } catch (e) {
          console.error('高亮关键词出错:', e);
        }
      }

      return `<pre class="http-content">${responseText}</pre>`;
    },

    // 提取错误关键词
    extractErrorKeywords(proof) {
      const keywords = [];

      // 从漏洞证明中提取关键词
      if (proof) {
        // 尝试提取包含"SQL错误信息"后面的内容
        const errorMatch = proof.match(/包含SQL错误信息[:：]\s*(.+)/i);
        if (errorMatch && errorMatch[1]) {
          const errorInfo = errorMatch[1].trim();
          // 拆分可能的多个关键词
          errorInfo.split(/[,，;；\s]+/).forEach(keyword => {
            if (keyword && keyword.length > 3) { // 只添加有意义的关键词
              keywords.push(keyword);
            }
          });
        }

        // 尝试直接从proof中提取常见SQL错误关键词
        const commonPatterns = [
          "SQL syntax", "MySQL", "SQL Server", "ORA-", "SQLSTATE",
          "syntax error", "mysqli", "Warning"
        ];

        for (const pattern of commonPatterns) {
          if (proof.includes(pattern)) {
            keywords.push(pattern);
          }
        }
      }

      // 如果从证明中提取不到关键词，添加常见的SQL错误关键词
      if (keywords.length === 0) {
        keywords.push(
          "SQL syntax", "MySQL", "SQLSTATE", "ORA-", "SQL Server",
          "Warning", "mysqli", "syntax error"
        );
      }

      return keywords;
    },

    // 转义正则表达式中的特殊字符
    escapeRegExp(string) {
      return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& 表示整个匹配的字符串
    },

    // 转义HTML，防止XSS攻击
    escapeHtml(unsafe) {
      return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
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

    // 是否为错误回显注入
    isSqlErrorMatch(row) {
      return row.vuln_subtype === 'error_based';
    },

    // 是否为基于时间的盲注
    isTimeBasedInjection(row) {
      return row.vuln_subtype === 'blind' && (row.proof || '').includes('时间');
    },

    // 获取错误匹配信息
    getErrorMatchInfo(row) {
      // 从proof中提取匹配信息，截取前15个字符
      const proof = row.proof || '';
      const matchInfo = proof.match(/包含SQL错误信息(.*)/);
      if (matchInfo && matchInfo[1]) {
        return matchInfo[1].slice(0, 15) + '...';
      }
      return '错误匹配';
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
  font-family: monospace;
  font-size: 13px;
  padding: 10px;
  border-radius: 4px;
  max-height: 500px;
  overflow-x: auto;
  overflow-y: auto;
  background-color: #2d2d2d;
  color: #f8f8f2;
}

.http-content {
  line-height: 1.5;
  margin: 0;
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
  color: #303133;
}

.highlight-content {
  font-family: Consolas, Monaco, 'Andale Mono', monospace;
  font-size: 13px;
  line-height: 1.6;
}

/* 参数和Payload高亮样式 */
.param-highlight {
  background-color: #409EFF;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
}

.payload-highlight {
  background-color: #F56C6C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-family: monospace;
}

/* SQL错误高亮样式 */
:deep(.sql-error-highlight) {
  background-color: #F56C6C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

/* HTTP内容样式改进 */
.detail-panel :deep(pre.http-content) {
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: monospace;
  font-size: 13px;
  padding: 10px;
  border-radius: 4px;
  max-height: 500px;
  overflow-x: auto;
  overflow-y: auto;
  background-color: #2d2d2d;
  color: #f8f8f2;
  line-height: 1.5;
  margin: 0;
}

.injection-details {
  margin-top: 20px;
  padding: 15px;
  background-color: #f0f9eb;
  border-radius: 4px;
  border-left: 4px solid #67C23A;
}

.injection-details h4 {
  margin-top: 0;
  margin-bottom: 10px;
  color: #67C23A;
}

.injection-details p {
  margin: 5px 0;
  line-height: 1.6;
}
</style>