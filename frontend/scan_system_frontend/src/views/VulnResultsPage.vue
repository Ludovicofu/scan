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
        <el-tab-pane label="信息收集" name="info_collection"></el-tab-pane>
      </el-tabs>
    </div>

    <!-- 信息收集结果 -->
    <InfoCollectionResults
      v-if="currentVulnType === 'info_collection'"
      :infoResults="results"
      :loading="loading"
      :currentPage="currentPage"
      :pageSize="pageSize"
      :total="totalResults"
      :showPagination="true"
      @size-change="handleSizeChange"
      @current-change="handlePageChange"
      @view-detail="showDetail"
      @delete-info="deleteResult"
    />

    <!-- SQL注入结果 -->
    <SqlInjectionResults
      v-else-if="currentVulnType === 'sql_injection'"
      :vulnResults="results"
      :loading="loading"
      :currentPage="currentPage"
      :pageSize="pageSize"
      :total="totalResults"
      :showPagination="true"
      @size-change="handleSizeChange"
      @current-change="handlePageChange"
      @view-detail="showDetail"
      @delete-vuln="deleteResult"
    />

    <!-- XSS跨站脚本结果 -->
    <XssResults
      v-else-if="currentVulnType === 'xss'"
      :vulnResults="results"
      :loading="loading"
      :currentPage="currentPage"
      :pageSize="pageSize"
      :total="totalResults"
      :showPagination="true"
      @size-change="handleSizeChange"
      @current-change="handlePageChange"
      @view-detail="showDetail"
      @delete-vuln="deleteResult"
    />

    <!-- 命令注入结果 -->
    <RceResults
      v-else-if="currentVulnType === 'command_injection'"
      :vulnResults="results"
      :loading="loading"
      :currentPage="currentPage"
      :pageSize="pageSize"
      :total="totalResults"
      :showPagination="true"
      @size-change="handleSizeChange"
      @current-change="handlePageChange"
      @view-detail="showDetail"
      @delete-vuln="deleteResult"
    />

    <!-- SSRF服务器端请求伪造结果 -->
    <SsrfResults
      v-else-if="currentVulnType === 'ssrf'"
      :vulnResults="results"
      :loading="loading"
      :currentPage="currentPage"
      :pageSize="pageSize"
      :total="totalResults"
      :showPagination="true"
      @size-change="handleSizeChange"
      @current-change="handlePageChange"
      @view-detail="showDetail"
      @delete-vuln="deleteResult"
    />

    <!-- 其他漏洞类型结果 - 通用表格 -->
    <GeneralVulnResults
      v-else
      :vulnResults="results"
      :loading="loading"
      :currentPage="currentPage"
      :pageSize="pageSize"
      :total="totalResults"
      @size-change="handleSizeChange"
      @current-change="handlePageChange"
      @view-detail="showDetail"
      @delete-vuln="deleteResult"
    />

    <!-- 结果详情对话框 -->
    <VulnDetailDialog
      :visible="detailDialogVisible"
      :vulnResult="selectedResult"
      :vulnType="currentVulnType"
      @close="detailDialogVisible = false"
      @verify="verifyVulnerability"
    />

    <!-- 信息收集详情对话框 -->
    <InfoDetailDialog
      v-if="currentVulnType === 'info_collection'"
      :visible="detailDialogVisible"
      :infoResult="selectedResult"
      @close="detailDialogVisible = false"
    />
  </div>
</template>

<script>
import ScanProgress from '@/components/common/ScanProgress.vue';
import ResultFilters from '@/components/common/ResultFilters.vue';
import SqlInjectionResults from '@/components/vuln/SqlInjectionResults.vue';
import XssResults from '@/components/vuln/XssResults.vue';
import RceResults from '@/components/vuln/RceResults.vue';
import SsrfResults from '@/components/vuln/SsrfResults.vue';
import GeneralVulnResults from '@/components/vuln/GeneralVulnResults.vue';
import VulnDetailDialog from '@/components/vuln/VulnDetailDialog.vue';
import InfoCollectionResults from '@/components/info/InfoCollectionResults.vue';
import InfoDetailDialog from '@/components/info/InfoDetailDialog.vue';
import { vulnScanAPI, infoCollectionAPI } from '@/services/api';
import { vulnScanWS, dataCollectionWS } from '@/services/websocket';
import { ElMessage, ElNotification, ElMessageBox } from 'element-plus';

export default {
  name: 'VulnResultsPage',
  components: {
    ScanProgress,
    ResultFilters,
    SqlInjectionResults,
    XssResults,
    RceResults,
    SsrfResults,
    GeneralVulnResults,
    VulnDetailDialog,
    InfoCollectionResults,
    InfoDetailDialog
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
      if (this.currentVulnType === 'info_collection') {
        this.initInfoCollectionWebSocket();
      } else {
        this.initVulnScanWebSocket();
      }
    },

    initVulnScanWebSocket() {
      // 连接WebSocket
      console.log("正在连接漏洞扫描WebSocket...");
      vulnScanWS.connect('ws://localhost:8000/ws/vuln_scan/')
        .then(() => {
          console.log("漏洞扫描WebSocket连接成功!");
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

    initInfoCollectionWebSocket() {
      // 连接WebSocket
      console.log("正在连接信息收集WebSocket...");
      dataCollectionWS.connect('ws://localhost:8000/ws/data_collection/')
        .then(() => {
          console.log("信息收集WebSocket连接成功!");
          // 添加事件监听器
          dataCollectionWS.addListener('scan_progress', this.handleScanProgress);
          dataCollectionWS.addListener('scan_result', this.handleInfoScanResult);
          dataCollectionWS.addListener('scan_status', this.handleScanStatus);
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          ElMessage.error('连接服务器失败，实时扫描进度将不可用');
        });
    },

    closeWebSocket() {
      // 移除事件监听器
      if (this.currentVulnType === 'info_collection') {
        dataCollectionWS.removeListener('scan_progress', this.handleScanProgress);
        dataCollectionWS.removeListener('scan_result', this.handleInfoScanResult);
        dataCollectionWS.removeListener('scan_status', this.handleScanStatus);
      } else {
        vulnScanWS.removeListener('scan_progress', this.handleScanProgress);
        vulnScanWS.removeListener('scan_result', this.handleScanResult);
        vulnScanWS.removeListener('scan_status', this.handleScanStatus);
      }
    },

    handleScanProgress(data) {
      // 处理扫描进度更新
      this.scanStatus = data.data.status;
      this.scanProgress = data.data.progress;
      this.currentScanUrl = data.data.url || '';
      this.scanMessage = data.data.message || '';
    },

    // 处理漏洞扫描结果
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

    // 处理信息收集结果
    handleInfoScanResult(data) {
      // 创建唯一标识符
      const resultKey = `info-${data.data.module}-${data.data.description}-${data.data.match_value}`;

      // 检查是否已经通知过这个结果
      if (this.notifiedResults.has(resultKey)) {
        console.log("忽略重复信息收集结果:", resultKey);
        return;
      }

      // 添加到已通知集合
      this.notifiedResults.add(resultKey);

      console.log("收到新的信息收集结果:", data);

      // 只有当前显示信息收集时
      if (this.currentVulnType === 'info_collection') {
        // 检查是否已在显示列表中
        if (!this.displayedResults.has(resultKey)) {
          // 保存到显示集合
          this.displayedResults.set(resultKey, data.data);

          // 添加到显示列表
          if (this.results.length < this.pageSize) {
            // 将新结果添加到列表头部
            this.results.unshift(data.data);
            this.totalResults++;
            console.log("添加信息收集结果到列表");
          }

          // 显示通知
          ElNotification({
            title: '信息收集',
            message: `发现新信息: ${data.data.description}`,
            type: 'info',
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
      if (this.currentVulnType === 'info_collection') {
        if (!dataCollectionWS.isConnected) {
          ElMessage.error('WebSocket未连接，无法启动扫描');
          return;
        }
        // 发送开始扫描消息
        dataCollectionWS.send({
          type: 'start_scan',
          options: {}
        });
      } else {
        if (!vulnScanWS.isConnected) {
          ElMessage.error('WebSocket未连接，无法启动扫描');
          return;
        }
        // 发送开始扫描消息
        vulnScanWS.send({
          type: 'start_scan',
          options: {}
        });
      }
    },

    stopScan() {
      if (this.currentVulnType === 'info_collection') {
        if (!dataCollectionWS.isConnected) {
          ElMessage.error('WebSocket未连接，无法停止扫描');
          return;
        }
        // 发送停止扫描消息
        dataCollectionWS.send({
          type: 'stop_scan'
        });
      } else {
        if (!vulnScanWS.isConnected) {
          ElMessage.error('WebSocket未连接，无法停止扫描');
          return;
        }
        // 发送停止扫描消息
        vulnScanWS.send({
          type: 'stop_scan'
        });
      }
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

        console.log("查询参数:", params);

        let response;

        // 根据当前tab获取不同类型的结果
        if (this.currentVulnType === 'info_collection') {
          response = await infoCollectionAPI.getScanResults(params);
        } else {
          // 使用按类型查询的API
          response = await vulnScanAPI.getVulnResultsByType(this.currentVulnType, params);
        }

        console.log("API响应:", response);

        this.results = response.results || [];
        this.totalResults = response.count || 0;

        // 更新已显示结果的集合
        this.displayedResults.clear();
        this.results.forEach(result => {
          let resultKey;
          if (this.currentVulnType === 'info_collection') {
            resultKey = `info-${result.module}-${result.description}-${result.match_value}`;
          } else {
            resultKey = `${result.vuln_type}-${result.name}-${result.url}`;
          }
          this.displayedResults.set(resultKey, result);
        });

        console.log("结果数量:", this.results.length);
      } catch (error) {
        console.error('获取结果失败', error);
        ElMessage.error('获取结果失败');
      } finally {
        this.loading = false;
      }
    },

    async deleteResult(id) {
      try {
        await ElMessageBox.confirm('确认删除此记录?', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        });

        if (this.currentVulnType === 'info_collection') {
          await infoCollectionAPI.deleteScanResult(id);
        } else {
          await vulnScanAPI.deleteScanResult(id);
        }

        ElMessage.success('删除成功');

        // 找到并从displayedResults中移除
        const resultToRemove = this.results.find(r => r.id === id);
        if (resultToRemove) {
          let key;
          if (this.currentVulnType === 'info_collection') {
            key = `info-${resultToRemove.module}-${resultToRemove.description}-${resultToRemove.match_value}`;
          } else {
            key = `${resultToRemove.vuln_type}-${resultToRemove.name}-${resultToRemove.url}`;
          }
          this.displayedResults.delete(key);
        }

        // 刷新结果列表
        this.fetchResults();
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除记录失败', error);
          ElMessage.error('删除记录失败');
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
    async handleVulnTypeChange() {
      // 切换tab时需要断开当前WebSocket并连接新的WebSocket
      this.closeWebSocket();

      this.currentPage = 1; // 重置为第一页
      await this.fetchResults();

      // 重新连接对应的WebSocket
      this.initWebSocket();
    },

    // 查看详情
    showDetail(row) {
      this.selectedResult = row;
      this.detailDialogVisible = true;
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
</style>