<template>
  <div class="vuln-results-page">
    <h1>漏洞检测结果</h1>

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
        <el-tab-pane label="RCE" name="command_injection"></el-tab-pane>
        <el-tab-pane label="SSRF" name="ssrf"></el-tab-pane>
        <el-tab-pane label="XXE" name="xxe"></el-tab-pane>
        <el-tab-pane label="其他" name="other"></el-tab-pane>
      </el-tabs>
    </div>

    <!-- SQL注入结果 -->
    <SqlInjectionResults
      v-if="currentVulnType === 'sql_injection'"
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

    <!-- 文件包含结果 -->
    <FileInclusionResults
      v-else-if="currentVulnType === 'file_inclusion'"
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

    <!-- RCE结果 -->
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
  </div>
</template>

<script>
import ResultFilters from '@/components/common/ResultFilters.vue';
import SqlInjectionResults from '@/components/vuln/SqlInjectionResults.vue';
import XssResults from '@/components/vuln/XssResults.vue';
import FileInclusionResults from '@/components/vuln/FileInclusionResults.vue';
import RceResults from '@/components/vuln/RceResults.vue';
import SsrfResults from '@/components/vuln/SsrfResults.vue';
import GeneralVulnResults from '@/components/vuln/GeneralVulnResults.vue';
import VulnDetailDialog from '@/components/vuln/VulnDetailDialog.vue';
import { vulnScanAPI } from '@/services/api';
import { vulnScanWS } from '@/services/websocket';
import { ElMessage, ElNotification, ElMessageBox } from 'element-plus';

export default {
  name: 'VulnResultsPage',
  components: {
    ResultFilters,
    SqlInjectionResults,
    XssResults,
    FileInclusionResults,
    RceResults,
    SsrfResults,
    GeneralVulnResults,
    VulnDetailDialog
  },
  data() {
    return {
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
          vulnScanWS.addListener('scan_result', this.handleScanResult);
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          ElMessage.error('连接服务器失败，实时扫描结果将不可用');
        });
    },
    closeWebSocket() {
      // 移除事件监听器
      vulnScanWS.removeListener('scan_result', this.handleScanResult);
    },

    handleScanResult(data) {
      // 创建更健壮的唯一标识符
      const resultKey = `${data.data.vuln_type}-${data.data.vuln_subtype}-${data.data.parameter}-${data.data.url}`;

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
        // 添加到显示列表时使用unshift保证新结果在顶部
        if (this.results.length >= this.pageSize) {
          // 如果已达到页大小，移除末尾项
          this.results.pop();
        }
        this.results.unshift(data.data);
        this.totalResults++;

        // 显示通知
        ElNotification({
          title: '漏洞发现',
          message: `发现新${this.getVulnTypeDisplay(data.data.vuln_type)}漏洞: ${data.data.name}`,
          type: this.getNotificationType(data.data.severity),
          duration: 5000
        });
      }
    },

    // 获取漏洞类型显示名称
    getVulnTypeDisplay(vulnType) {
      const vulnTypeMap = {
        'sql_injection': 'SQL注入',
        'xss': 'XSS跨站脚本',
        'file_inclusion': '文件包含',
        'command_injection': 'RCE', // 将命令注入改为RCE
        'ssrf': 'SSRF',
        'xxe': 'XXE',
        'other': '其他'
      };
      return vulnTypeMap[vulnType] || vulnType;
    },

    // 添加新方法，根据严重程度返回通知类型
    getNotificationType(severity) {
      switch(severity) {
        case 'high': return 'error';
        case 'medium': return 'warning';
        case 'low': return 'info';
        default: return 'warning';
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