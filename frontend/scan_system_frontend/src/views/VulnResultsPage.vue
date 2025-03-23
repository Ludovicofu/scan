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
      width="70%"
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
          <el-collapse>
            <el-collapse-item title="HTTP请求" name="request">
              <pre>{{ selectedResult.request }}</pre>
            </el-collapse-item>
            <el-collapse-item title="HTTP响应" name="response">
              <pre>{{ selectedResult.response }}</pre>
            </el-collapse-item>
          </el-collapse>
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
      selectedResult: null
    };
  },
  created() {
    this.initWebSocket();
    this.fetchResults();
  },
  beforeUnmount() {
    this.closeWebSocket();
  },
  methods: {
    // WebSocket相关方法
    initWebSocket() {
      // 连接WebSocket
      vulnScanWS.connect('ws://localhost:8000/ws/vuln_scan/')
        .then(() => {
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
      // 处理扫描结果
      if (data.data.scan_type === this.currentScanType) {
        // 如果是当前显示的扫描类型，则添加到结果列表
        if (this.results.length < this.pageSize) {
          this.results.unshift(data.data);
          this.totalResults++;
        } else {
          // 通知用户有新结果
          ElNotification({
            title: '漏洞发现',
            message: `发现新的漏洞: ${data.data.name}`,
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
        let response;
        const params = {
          ...this.filters,
          page: this.currentPage,
          page_size: this.pageSize
        };

        if (this.currentScanType === 'passive') {
          response = await vulnScanAPI.getPassiveScanResults(params);
        } else {
          response = await vulnScanAPI.getActiveScanResults(params);
        }

        this.results = response.results || [];
        this.totalResults = response.count || 0;
      } catch (error) {
        console.error('获取扫描结果失败', error);
        ElMessage.error('获取扫描结果失败');
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

    // 工具方法
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    },
    getSeverityType(severity) {
      const severityMap = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
        'info': 'success'
      };
      return severityMap[severity] || 'info';
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

.http-details pre {
  white-space: pre-wrap;
  word-wrap: break-word;
  background-color: #f5f7fa;
  padding: 10px;
  font-family: monospace;
  font-size: 13px;
  border-radius: 4px;
  max-height: 300px;
  overflow-y: auto;
}
</style>