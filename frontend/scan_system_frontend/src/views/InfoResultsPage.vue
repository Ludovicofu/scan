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
          <el-descriptions-item label="匹配值">{{ selectedResult.match_value }}</el-descriptions-item>
          <el-descriptions-item label="扫描日期">{{ formatDate(selectedResult.scan_date) }}</el-descriptions-item>
        </el-descriptions>

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
                <div v-if="selectedResult.match_value" class="highlight-section">
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
        localStorage.setItem('infoResultNotified', JSON.stringify(Array.from(this.notifiedResults)));
      } catch (e) {
        console.error('保存去重数据失败', e);
      }
    },
    loadDeduplicationData() {
      try {
        // 从localStorage加载通知过的结果
        const notifiedData = localStorage.getItem('infoResultNotified');
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
      dataCollectionWS.connect('ws://localhost:8000/ws/data_collection/')
        .then(() => {
          console.log("WebSocket连接成功!");
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
    // 修改扫描结果处理方法，添加处理请求和响应数据
    handleScanResult(data) {
      // 创建唯一标识符
      const resultKey = `${data.data.module}-${data.data.description}-${data.data.match_value}`;

      // 检查是否已经通知过这个结果
      if (this.notifiedResults.has(resultKey)) {
        console.log("忽略重复结果:", resultKey);
        return;
      }

      // 添加到已通知集合
      this.notifiedResults.add(resultKey);
      // 定期保存去重数据
      this.saveDeduplicationData();

      console.log("收到新的扫描结果:", data);
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
            console.log("添加结果到列表");
          }

          // 无论如何都显示通知
          ElNotification({
            title: '发现新结果',
            message: `${data.data.module_display}: ${data.data.description}`,
            type: 'success',
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
      if (!dataCollectionWS.isConnected) {
        ElMessage.error('WebSocket未连接，无法启动扫描');
        return;
      }

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
      console.log("获取扫描结果, 类型:", this.currentScanType);
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

        console.log("API响应:", response);

        this.results = response.results || [];
        this.totalResults = response.count || 0;

        // 更新已显示结果的集合
        this.displayedResults.clear();
        this.results.forEach(result => {
          const resultKey = `${result.module}-${result.description}-${result.match_value}`;
          this.displayedResults.set(resultKey, result);
        });

        console.log("结果数量:", this.results.length);
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

        // 找到并从displayedResults中移除
        const resultToRemove = this.results.find(r => r.id === id);
        if (resultToRemove) {
          const key = `${resultToRemove.module}-${resultToRemove.description}-${resultToRemove.match_value}`;
          this.displayedResults.delete(key);
        }

        // 刷新结果列表
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
</style>