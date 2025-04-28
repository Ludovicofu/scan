<!-- 修复 frontend/scan_system_frontend/src/views/InfoResultsPage.vue 中重复通知和结果显示问题 -->
<template>
  <div class="info-results-page">
    <h1>信息收集结果</h1>

    <!-- 扫描进度 -->
    <ScanProgress
      title="信息收集扫描进度"
      :status="scanStatus"
      :progress="scanProgress"
      :current-url="currentScanUrl"
      :message="scanMessage"
      @start="startScan"
      @stop="stopScan"
    />

    <!-- 过滤器 -->
    <ResultFilters
      type="info"
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
          prop="module_display"
          label="模块"
          width="150"
        ></el-table-column>

        <el-table-column
          prop="description"
          label="描述"
          width="180"
        ></el-table-column>

        <el-table-column
          v-if="currentScanType === 'active'"
          prop="behavior"
          label="行为"
          width="250"
        ></el-table-column>

        <el-table-column
          prop="rule_type"
          label="规则类型"
          width="150"
        ></el-table-column>

        <el-table-column
          prop="match_value"
          label="匹配值"
          show-overflow-tooltip
        >
          <template #default="scope">
            <!-- 对端口扫描结果特殊处理 -->
            <span v-if="scope.row.is_port_scan && scope.row.port_display">
              {{ scope.row.port_display }}
            </span>
            <span v-else>{{ scope.row.match_value }}</span>
          </template>
        </el-table-column>

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
      title="扫描结果详情"
      v-model="detailDialogVisible"
      width="80%"
    >
      <div v-if="selectedResult">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="资产">{{ selectedResult.asset }}</el-descriptions-item>
          <el-descriptions-item label="模块">{{ selectedResult.module_display }}</el-descriptions-item>
          <el-descriptions-item label="描述">{{ selectedResult.description }}</el-descriptions-item>
          <el-descriptions-item v-if="selectedResult.behavior" label="行为">{{ selectedResult.behavior }}</el-descriptions-item>
          <el-descriptions-item label="规则类型">{{ selectedResult.rule_type }}</el-descriptions-item>
          <el-descriptions-item label="扫描日期">{{ formatDate(selectedResult.scan_date) }}</el-descriptions-item>
        </el-descriptions>

        <!-- 端口扫描结果特殊显示 -->
        <div v-if="selectedResult.rule_type === 'port'" class="port-scan-results">
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
                    <el-tooltip
                      v-if="isBinaryData(scope.row.banner)"
                      content="点击查看十六进制数据"
                      placement="top"
                      effect="light"
                    >
                      <div class="binary-data" @click="scope.row.showHex = !scope.row.showHex">
                        {{ scope.row.showHex ? scope.row.hexData : scope.row.banner }}
                      </div>
                    </el-tooltip>
                    <span v-else>{{ scope.row.banner }}</span>
                  </div>
                </template>
              </el-table-column>
            </el-table>
          </div>
        </div>
        <!-- 其他类型结果显示 -->
        <div v-else>
          <el-divider content-position="left">匹配值</el-divider>
          <div class="match-value">{{ selectedResult.match_value }}</div>
        </div>

        <div class="detail-content">
          <el-divider content-position="left">请求/响应详情</el-divider>
          <el-tabs>
            <el-tab-pane label="请求内容">
              <div class="detail-panel">
                <!-- 使用selectedResult中的实际请求数据 -->
                <div v-if="selectedResult.behavior" class="highlight-section">
                  <div class="highlight-title">行为路径:</div>
                  <div class="highlight-content" v-html="highlightBehavior(selectedResult.request_data, selectedResult.behavior)"></div>
                </div>
                <pre>{{ selectedResult.request_data || '无请求数据' }}</pre>
              </div>
            </el-tab-pane>
            <el-tab-pane label="响应内容">
              <div class="detail-panel">
                <!-- 使用selectedResult中的实际响应数据 -->
                <div v-if="selectedResult.match_value && selectedResult.rule_type !== 'port'" class="highlight-section">
                  <div class="highlight-title">匹配值:</div>
                  <div class="highlight-content" v-html="highlightMatchValue(selectedResult.response_data, selectedResult.match_value)"></div>
                </div>
                <pre>{{ selectedResult.response_data || '无响应数据' }}</pre>
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
import { infoCollectionAPI } from '@/services/api';
import { dataCollectionWS } from '@/services/websocket';
import { ElMessage, ElNotification, ElMessageBox } from 'element-plus';

export default {
  name: 'InfoResultsPage',
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

      // 去重相关
      resultCache: new Map(), // 用于跟踪已经显示的结果，键为 ID
      notificationCache: new Map(), // 用于跟踪已经通知的结果，键为 asset-module-description-rule_type
      resultIdSet: new Set(), // 用于跟踪已显示的结果ID

      // 通知节流控制
      notificationThrottleTime: 2000, // 相同类型通知的最小间隔(ms)
      lastNotificationTime: {} // 记录每种类型通知的最后时间
    };
  },
  computed: {
    // 解析端口扫描结果为表格数据
    parsedPortResults() {
      if (!this.selectedResult || this.selectedResult.rule_type !== 'port' || !this.selectedResult.match_value) {
        return [];
      }

      let result = [];
      const matchValue = this.selectedResult.match_value || '';

      // 处理单行和多行情况
      const lines = matchValue.includes('\n') ? matchValue.split('\n') : [matchValue];

      lines.forEach(line => {
        if (!line || !line.includes(':')) return;

        const [port, ...bannerParts] = line.split(':');
        const banner = bannerParts.join(':').trim();

        // 提取十六进制数据（如果存在）
        let hexData = '';
        if (this.isBinaryData(banner)) {
          const hexMatch = banner.match(/前\d+字节: ([0-9a-f]+)/i);
          if (hexMatch && hexMatch[1]) {
            hexData = this.formatHexData(hexMatch[1]);
          }
        }

        result.push({
          port: port.trim(),
          banner: banner || '无Banner信息',
          hexData,
          showHex: false
        });
      });

      return result;
    }
  },
  created() {
    this.initWebSocket();
    this.fetchResults();

    // 从 localStorage 恢复缓存数据
    this.loadCacheFromStorage();
  },
  beforeUnmount() {
    this.closeWebSocket();

    // 保存缓存数据到 localStorage
    this.saveCacheToStorage();
  },
  methods: {
    // 缓存持久化处理
    loadCacheFromStorage() {
      try {
        // 恢复结果ID集合
        const cachedIds = localStorage.getItem('infoResultIdSet');
        if (cachedIds) {
          this.resultIdSet = new Set(JSON.parse(cachedIds));
          console.log(`已从存储恢复 ${this.resultIdSet.size} 个结果ID`);
        }

        // 恢复通知缓存
        const cachedNotifications = localStorage.getItem('infoNotificationCache');
        if (cachedNotifications) {
          this.notificationCache = new Map(JSON.parse(cachedNotifications));
          console.log(`已从存储恢复 ${this.notificationCache.size} 个通知记录`);
        }
      } catch (error) {
        console.error('从存储恢复缓存失败', error);
      }
    },

    saveCacheToStorage() {
      try {
        // 保存结果ID集合
        localStorage.setItem('infoResultIdSet', JSON.stringify([...this.resultIdSet]));

        // 保存通知缓存
        localStorage.setItem('infoNotificationCache', JSON.stringify([...this.notificationCache]));

        console.log('缓存数据已保存到存储');
      } catch (error) {
        console.error('保存缓存到存储失败', error);
      }
    },

    // WebSocket相关方法
    initWebSocket() {
      // 连接WebSocket
      console.log("正在连接WebSocket...");
      dataCollectionWS.connect('ws://localhost:8000/ws/data_collection/')
        .then(() => {
          console.log("WebSocket连接成功!");

          // 重置服务端的缓存，确保不会遗漏结果
          dataCollectionWS.send({
            type: 'reset_cache',
            reset_global: false // 不清除全局缓存，只清除本次连接的缓存
          });

          // 添加事件监听器
          dataCollectionWS.addListener('scan_progress', this.handleScanProgress);
          dataCollectionWS.addListener('scan_result', this.handleScanResult);
          dataCollectionWS.addListener('scan_status', this.handleScanStatus);
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          ElMessage.error('连接服务器失败，实时扫描进度将不可用');
        });
    },
    closeWebSocket() {
      // 移除事件监听器
      dataCollectionWS.removeListener('scan_progress', this.handleScanProgress);
      dataCollectionWS.removeListener('scan_result', this.handleScanResult);
      dataCollectionWS.removeListener('scan_status', this.handleScanStatus);
    },
    handleScanProgress(data) {
      // 处理扫描进度更新
      this.scanStatus = data.data.status;
      this.scanProgress = data.data.progress;
      this.currentScanUrl = data.data.url || '';
      this.scanMessage = data.data.message || '';
    },

    // 修改后的处理扫描结果方法
    handleScanResult(data) {
      // 检查消息格式
      if (!data || !data.data) {
        console.error("无效的扫描结果数据");
        return;
      }

      const resultData = data.data;

      // 检查是否是当前显示的扫描类型
      if (resultData.scan_type !== this.currentScanType) {
        console.log(`跳过不匹配当前扫描类型的结果: ${resultData.scan_type} != ${this.currentScanType}`);
        return;
      }

      // 构建结果唯一标识
      const resultId = resultData.id;
      const resultKey = `${resultData.asset}-${resultData.module}-${resultData.description}-${resultData.rule_type}`;

      // 检查结果ID是否已存在（如果有ID）
      if (resultId && this.resultIdSet.has(resultId)) {
        console.log(`跳过已处理的结果ID: ${resultId}`);
        return;
      }

      // 检查结果唯一标识是否已存在于缓存中
      if (this.notificationCache.has(resultKey)) {
        console.log(`跳过重复结果通知: ${resultKey}`);
        return;
      }

      // 添加到缓存中
      if (resultId) {
        this.resultIdSet.add(resultId);
      }
      this.notificationCache.set(resultKey, true);

      // 将结果添加到结果列表的头部，最多添加到当前页长度
      if (this.results.length >= this.pageSize) {
        // 如果已达到页大小，移除末尾项
        this.results.pop();
      }
      this.results.unshift(resultData);
      this.totalResults++;

      // 构建通知消息并显示
      this.showResultNotification(resultData);
    },

    // 添加一个专门的通知显示方法
    showResultNotification(resultData) {
      // 获取当前时间戳
      const now = Date.now();

      // 确定通知类型
      let notificationType = 'info';
      let notificationTitle = '';
      let notificationMessage = '';

      // 根据结果类型设置通知内容
      if (resultData.rule_type === 'port') {
        // 端口扫描结果
        notificationType = 'warning';
        notificationTitle = '端口扫描结果';
        notificationMessage = `发现开放端口: ${resultData.port_display || resultData.match_value.split("\n")[0]}`;
      } else {
        // 根据模块设置不同的通知
        switch(resultData.module) {
          case 'network':
            notificationTitle = '网络信息';
            notificationMessage = `发现网络信息: ${resultData.description}`;
            break;
          case 'os':
            notificationTitle = '操作系统信息';
            notificationMessage = `发现操作系统信息: ${resultData.description}`;
            break;
          case 'component':
            notificationTitle = '组件与服务信息';
            notificationMessage = `发现组件信息: ${resultData.description}`;
            break;
          default:
            notificationTitle = '扫描结果';
            notificationMessage = `发现新结果: ${resultData.description}`;
        }
      }

      // 节流通知显示
      const lastTime = this.lastNotificationTime[resultData.module] || 0;
      if (now - lastTime > this.notificationThrottleTime) {
        // 更新最后通知时间
        this.lastNotificationTime[resultData.module] = now;

        // 显示通知
        ElNotification({
          title: notificationTitle,
          message: notificationMessage,
          type: notificationType,
          duration: 3000
        });
      } else {
        console.log(`通知频率限制: ${resultData.module}, 跳过显示`);
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
      if (!dataCollectionWS.isConnected) {
        ElMessage.error('WebSocket未连接，无法启动扫描');
        return;
      }

      // 先重置缓存，确保不会漏掉新的扫描结果
      dataCollectionWS.send({
        type: 'reset_cache'
      });

      // 发送开始扫描消息
      dataCollectionWS.send({
        type: 'start_scan',
        options: {}
      });
    },
    stopScan() {
      if (!dataCollectionWS.isConnected) {
        ElMessage.error('WebSocket未连接，无法停止扫描');
        return;
      }

      // 发送停止扫描消息
      dataCollectionWS.send({
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

        console.log("查询参数:", params);

        if (this.currentScanType === 'passive') {
          response = await infoCollectionAPI.getPassiveScanResults(params);
        } else {
          response = await infoCollectionAPI.getActiveScanResults(params);
        }

        // 处理API响应
        this.results = response.results || [];
        this.totalResults = response.count || 0;

        // 更新已处理的结果IDs
        this.results.forEach(result => {
          if (result.id) {
            this.resultIdSet.add(result.id);
          }
          // 更新通知缓存
          const resultKey = `${result.asset}-${result.module}-${result.description}-${result.rule_type}`;
          this.notificationCache.set(resultKey, true);
        });

        console.log(`加载了 ${this.results.length} 条结果`);
      } catch (error) {
        console.error('获取扫描结果失败', error);
        ElMessage.error('获取扫描结果失败');
      } finally {
        this.loading = false;
      }
    },

    async deleteResult(id) {
      try {
        await ElMessageBox.confirm('确认删除该扫描结果?', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        });

        await infoCollectionAPI.deleteScanResult(id);
        ElMessage.success('删除成功');

        // 从结果ID集合中移除
        this.resultIdSet.delete(id);

        // 从当前结果列表中移除
        const index = this.results.findIndex(item => item.id === id);
        if (index !== -1) {
          // 移除对应的缓存项
          const result = this.results[index];
          const resultKey = `${result.asset}-${result.module}-${result.description}-${result.rule_type}`;
          this.notificationCache.delete(resultKey);

          // 从列表移除
          this.results.splice(index, 1);
          this.totalResults--;
        }

        // 刷新结果列表
        if (this.results.length === 0 && this.currentPage > 1) {
          this.currentPage--;
        }
        this.fetchResults();
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除扫描结果失败', error);
          ElMessage.error('删除扫描结果失败');
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

    // 高亮显示行为和匹配值
    highlightBehavior(text, behavior) {
      if (!text || !behavior) return text;

      // 对behavior进行转义，以便正确用于正则表达式
      const escapedBehavior = behavior.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // 创建正则表达式，使用全局搜索和不区分大小写选项
      const regex = new RegExp(escapedBehavior, 'gi');

      // 用带有高亮的HTML替换匹配的文本
      return text.replace(regex, match => `<span class="highlight-behavior">${match}</span>`);
    },

    highlightMatchValue(text, matchValue) {
      if (!text || !matchValue) return text;

      // 对matchValue进行转义，以便正确用于正则表达式
      const escapedMatchValue = matchValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // 创建正则表达式，使用全局搜索和不区分大小写选项
      const regex = new RegExp(escapedMatchValue, 'gi');

      // 用带有高亮的HTML替换匹配的文本
      return text.replace(regex, match => `<span class="highlight-match">${match}</span>`);
    },

    /**
     * 检查Banner是否是二进制数据描述
     * @param {string} banner Banner文本
     * @returns {boolean} 是否为二进制数据
     */
    isBinaryData(banner) {
      return banner && (
        banner.includes('二进制数据') ||
        banner.includes('前20字节:') ||
        banner.includes('前32字节:') ||
        banner.includes('前16字节:')
      );
    },

    /**
     * 格式化十六进制数据，每2个字符加一个空格
     * @param {string} hex 十六进制字符串
     * @returns {string} 格式化后的十六进制字符串
     */
    formatHexData(hex) {
      let result = '';
      for (let i = 0; i < hex.length; i += 2) {
        result += hex.substr(i, 2) + ' ';
      }
      return result.trim();
    },

    // 工具方法
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    }
  }
};
</script>

<style scoped>
.info-results-page {
  padding: 20px;
}

h1 {
  margin-bottom: 20px;
  font-size: 24px;
  color: #303133;
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

/* 新增端口扫描结果样式 */
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

.binary-data {
  cursor: pointer;
  padding: 2px 4px;
  background-color: #f5f7fa;
  border-radius: 3px;
  color: #303133;
  transition: background-color 0.2s;
}

.binary-data:hover {
  background-color: #e6ebf5;
}

/* 其他类型结果显示 */
.match-value {
  background-color: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  font-family: monospace;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>