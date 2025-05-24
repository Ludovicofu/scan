<template>
  <div class="vuln-results-page">
    <h1>漏洞检测结果</h1>

    <!-- 过滤器 - 已移除 -->

    <!-- 漏洞类型选择 -->
    <div class="vuln-type-tabs">
      <el-tabs v-model="currentVulnType" @tab-click="handleVulnTypeChange">
        <el-tab-pane label="SQL注入" name="sql_injection"></el-tab-pane>
        <el-tab-pane label="XSS" name="xss"></el-tab-pane>
        <el-tab-pane label="文件包含" name="file_inclusion"></el-tab-pane>
        <el-tab-pane label="RCE" name="command_injection"></el-tab-pane>
        <el-tab-pane label="SSRF" name="ssrf"></el-tab-pane>
      </el-tabs>

      <!-- 只保留WebSocket状态指示器，移除按钮 -->
      <div class="ws-status-indicator">
        <el-tag
          :type="isWebSocketConnected ? 'success' : 'danger'"
          size="small"
          class="ws-status-tag"
        >
          {{ isWebSocketConnected ? 'WebSocket已连接' : 'WebSocket未连接' }}
        </el-tag>
      </div>
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
import SqlInjectionResults from '@/components/vuln/SqlInjectionResults.vue';
import XssResults from '@/components/vuln/XssResults.vue';
import FileInclusionResults from '@/components/vuln/FileInclusionResults.vue';
import RceResults from '@/components/vuln/RceResults.vue';
import SsrfResults from '@/components/vuln/SsrfResults.vue';
import VulnDetailDialog from '@/components/vuln/VulnDetailDialog.vue';
import { vulnScanAPI } from '@/services/api';
import { vulnScanWS } from '@/services/websocket';
import { ElMessage, ElNotification, ElMessageBox } from 'element-plus';

export default {
  name: 'VulnResultsPage',
  components: {
    SqlInjectionResults,
    XssResults,
    FileInclusionResults,
    RceResults,
    SsrfResults,
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

      // 当前漏洞类型
      currentVulnType: 'sql_injection', // 默认显示SQL注入

      // 详情对话框
      detailDialogVisible: false,
      selectedResult: null,

      // WebSocket相关
      isWebSocketConnected: false,
      wsCheckInterval: null,

      // 去重相关
      resultCache: new Map(), // 用于存储已经显示的结果，键为ID
      notifiedResults: new Set(), // 用于存储已经通知的结果ID
      processedNotifications: new Set(), // 用于去重通知消息
      completedNotifications: new Set(), // 用于存储已显示的完成通知

      // 通知节流
      lastNotificationTime: 0,
      notificationThrottleTime: 3000, // 3秒内不重复显示同类型通知

      // 进度通知记录
      lastProgressStatus: null,
      lastProgressMessageTime: 0,
      progressMessageThrottleTime: 5000, // 5秒内不重复显示相同状态的进度通知
    };
  },
  created() {
    // 添加页面可见性变化监听
    document.addEventListener('visibilitychange', this.handleVisibilityChange);

    // 从LocalStorage恢复缓存
    this.loadCacheFromStorage();

    // 连接WebSocket
    this.initWebSocket();

    // 开始WebSocket状态检查
    this.startWebSocketCheck();

    // 获取初始数据
    this.fetchResults();
  },
  beforeUnmount() {
    // 移除页面可见性监听
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);

    // 清除定时器
    this.stopWebSocketCheck();

    // 断开WebSocket
    this.closeWebSocket();

    // 保存缓存到LocalStorage
    this.saveCacheToStorage();
  },
  methods: {
    // LocalStorage缓存处理
    loadCacheFromStorage() {
      try {
        // 恢复已通知结果集
        const notifiedData = localStorage.getItem('vulnResultNotified');
        if (notifiedData) {
          this.notifiedResults = new Set(JSON.parse(notifiedData));
          console.log(`已从存储恢复 ${this.notifiedResults.size} 个已通知结果记录`);
        }

        // 恢复结果缓存
        const resultCacheData = localStorage.getItem('vulnResultCache');
        if (resultCacheData) {
          this.resultCache = new Map(JSON.parse(resultCacheData));
          console.log(`已从存储恢复 ${this.resultCache.size} 个结果缓存记录`);
        }

        // 恢复已处理通知集合
        const processedNotifications = localStorage.getItem('processedNotifications');
        if (processedNotifications) {
          this.processedNotifications = new Set(JSON.parse(processedNotifications));
          console.log(`已从存储恢复 ${this.processedNotifications.size} 个已处理通知记录`);
        }

        // 恢复已完成通知集合
        const completedNotifications = localStorage.getItem('completedNotifications');
        if (completedNotifications) {
          this.completedNotifications = new Set(JSON.parse(completedNotifications));
        }
      } catch (error) {
        console.error('从LocalStorage恢复缓存失败', error);
      }
    },

    saveCacheToStorage() {
      try {
        // 保存已通知结果集
        localStorage.setItem('vulnResultNotified', JSON.stringify(Array.from(this.notifiedResults)));

        // 保存结果缓存
        localStorage.setItem('vulnResultCache', JSON.stringify(Array.from(this.resultCache)));

        // 保存已处理通知集合
        localStorage.setItem('processedNotifications', JSON.stringify(Array.from(this.processedNotifications)));

        // 保存已完成通知集合
        localStorage.setItem('completedNotifications', JSON.stringify(Array.from(this.completedNotifications)));

        console.log('缓存数据已保存到LocalStorage');
      } catch (error) {
        console.error('保存缓存到LocalStorage失败', error);
      }
    },

    // 页面可见性处理
    handleVisibilityChange() {
      if (document.visibilityState === 'visible') {
        // 页面变为可见时，检查WebSocket连接状态并刷新数据
        console.log('页面变为可见，检查WebSocket连接');
        this.checkWebSocketStatus();
        this.fetchResults();
      }
    },

    // WebSocket相关方法
    initWebSocket() {
      // 连接WebSocket
      console.log("正在连接WebSocket...");

      vulnScanWS.connect('ws://localhost:8000/ws/vuln_scan/')
        .then(() => {
          console.log("WebSocket连接成功!");
          this.isWebSocketConnected = true;

          // 添加事件监听器
          vulnScanWS.addListener('scan_result', this.handleScanResult);
          vulnScanWS.addListener('scan_progress', this.handleScanProgress);
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          this.isWebSocketConnected = false;

          // 自动尝试重连
          this.attemptReconnect();
        });
    },

    closeWebSocket() {
      // 移除事件监听器
      vulnScanWS.removeListener('scan_result', this.handleScanResult);
      vulnScanWS.removeListener('scan_progress', this.handleScanProgress);

      // 断开连接
      vulnScanWS.disconnect();
      this.isWebSocketConnected = false;
    },

    attemptReconnect() {
      // 3秒后尝试重连
      setTimeout(() => {
        console.log('自动尝试重连WebSocket');
        this.initWebSocket();
      }, 3000);
    },

    startWebSocketCheck() {
      // 每30秒检查一次WebSocket状态
      this.wsCheckInterval = setInterval(() => {
        this.checkWebSocketStatus();
      }, 30000);
    },

    stopWebSocketCheck() {
      if (this.wsCheckInterval) {
        clearInterval(this.wsCheckInterval);
        this.wsCheckInterval = null;
      }
    },

    checkWebSocketStatus() {
      // 更新当前连接状态
      const wasConnected = this.isWebSocketConnected;
      this.isWebSocketConnected = vulnScanWS.isConnected;

      // 如果状态从连接变为断开，尝试重连
      if (wasConnected && !this.isWebSocketConnected) {
        console.log('检测到WebSocket连接已断开，尝试重连');
        this.attemptReconnect();
      }
    },

    // WebSocket消息处理
    handleScanResult(message) {
      // 忽略无效消息
      if (!message || !message.data) {
        return;
      }

      const resultData = message.data;

      // 生成结果的唯一标识符
      const resultKey = this.getResultKey(resultData);

      // 检查是否已处理过此结果
      if (this.notifiedResults.has(resultKey)) {
        console.log('跳过已通知的结果:', resultKey);
        return;
      }

      console.log('收到新的漏洞扫描结果:', resultKey);

      // 标记为已通知
      this.notifiedResults.add(resultKey);

      // 检查是否为当前显示的漏洞类型
      if (resultData.vuln_type === this.currentVulnType) {
        // 将新结果添加到顶部
        this.results.unshift(resultData);

        // 如果当前页面结果超过页面大小，移除最后一条
        if (this.results.length > this.pageSize) {
          this.results.pop();
        }

        // 更新总数
        this.totalResults++;

        // 保存结果到缓存
        if (resultData.id) {
          this.resultCache.set(resultData.id, resultData);
        }
      } else {
        // 虽然不是当前类型，但仍保存到缓存
        if (resultData.id) {
          this.resultCache.set(resultData.id, resultData);
        }
      }

      // 显示通知（应用节流控制）
      this.showNotificationForResult(resultData);

      // 保存缓存
      this.saveCacheToStorage();
    },

    handleScanProgress(message) {
      // 忽略无效消息
      if (!message || !message.data) {
        return;
      }

      const progressData = message.data;
      const status = progressData.status;
      const messageText = progressData.message || '';

      // 创建唯一的进度消息标识
      const progressKey = `${status}-${messageText}`;

      // 检查是否是重复的相同状态消息
      const now = Date.now();
      const isRecentMessage = (status === this.lastProgressStatus) &&
                             (now - this.lastProgressMessageTime < this.progressMessageThrottleTime);

      // 如果是最近显示过的相同状态消息，跳过
      if (isRecentMessage) {
        console.log('跳过相同状态的进度通知:', progressKey);
        return;
      }

      // 更新最后进度状态和时间
      this.lastProgressStatus = status;
      this.lastProgressMessageTime = now;

      console.log('扫描进度更新:', progressData);

      // 根据状态显示不同通知
      switch(status) {
        case 'started':
          // 扫描开始通知(通常不需要显示)
          break;

        case 'completed': {
          // 在case块之前声明变量，避免ESLint错误
          let completedKey = `completed-${new Date().toDateString()}`;

          // 检查是否已经显示过完成通知
          if (!this.completedNotifications.has(completedKey)) {
            ElNotification({
              title: '扫描完成',
              message: messageText || '漏洞扫描已完成',
              type: 'success',
              duration: 3000
            });

            // 标记此完成通知已显示
            this.completedNotifications.add(completedKey);

            // 保存已处理通知记录
            this.saveCacheToStorage();

            // 刷新结果
            this.fetchResults();
          }
          break;
        }

        case 'error':
          // 错误通知一定要显示
          ElNotification({
            title: '扫描错误',
            message: messageText || '扫描过程中发生错误',
            type: 'error',
            duration: 5000
          });
          break;

        default:
          // 忽略其他状态
          break;
      }
    },

    showNotificationForResult(result) {
      // 检查通知节流
      const now = Date.now();
      if (now - this.lastNotificationTime < this.notificationThrottleTime) {
        console.log('通知被节流，跳过');
        return;
      }

      // 更新最后通知时间
      this.lastNotificationTime = now;

      // 构造唯一的通知标识
      const notificationKey = this.getResultKey(result);

      // 检查是否已经显示过此通知
      if (this.processedNotifications.has(notificationKey)) {
        console.log('跳过已显示的通知:', notificationKey);
        return;
      }

      // 构造通知内容
      const title = `发现${this.getVulnTypeDisplay(result.vuln_type)}漏洞`;
      let message = `${result.name}`;

      if (result.parameter) {
        message += ` (参数: ${result.parameter})`;
      }

      // 显示通知
      ElNotification({
        title: title,
        message: message,
        type: this.getNotificationTypeFromSeverity(result.severity),
        duration: 3000, // 减少显示时间
        onClick: () => {
          // 点击通知时切换到对应漏洞类型并显示详情
          if (this.currentVulnType !== result.vuln_type) {
            this.currentVulnType = result.vuln_type;
            this.fetchResults();
          }
          this.showDetail(result);
        }
      });

      // 标记此通知已显示
      this.processedNotifications.add(notificationKey);

      // 保存已处理通知记录
      this.saveCacheToStorage();
    },

    // 获取结果的唯一标识
    getResultKey(result) {
      // 如果有ID，使用ID作为键的一部分
      const idPart = result.id ? `-${result.id}` : '';

      // 创建唯一标识
      return `${result.vuln_type}-${result.vuln_subtype || ''}-${result.parameter || ''}-${result.url}${idPart}`;
    },

    // 获取漏洞类型显示名称
    getVulnTypeDisplay(vulnType) {
      const vulnTypeMap = {
        'sql_injection': 'SQL注入',
        'xss': 'XSS跨站脚本',
        'file_inclusion': '文件包含',
        'command_injection': '命令执行',
        'ssrf': 'SSRF'
      };
      return vulnTypeMap[vulnType] || vulnType;
    },

    // 根据严重性获取通知类型
    getNotificationTypeFromSeverity(severity) {
      switch(severity) {
        case 'high': return 'error';
        case 'medium': return 'warning';
        case 'low': return 'info';
        default: return 'success';
      }
    },

    // 数据操作方法
    async fetchResults() {
      this.loading = true;
      try {
        const params = {
          page: this.currentPage,
          page_size: this.pageSize
        };
        
        console.log("获取漏洞结果, 参数:", params);
        
        // 使用按类型查询的API
        const response = await vulnScanAPI.getVulnResultsByType(this.currentVulnType, params);
        
        // 处理响应数据
        this.results = response.results || [];
        this.totalResults = response.count || 0;
        
        console.log(`获取到 ${this.results.length} 条漏洞结果, 总数: ${this.totalResults}`);
        
        // 更新缓存
        this.results.forEach(result => {
          // 添加到结果缓存
          if (result.id) {
            this.resultCache.set(result.id, result);
          }
          
          // 标记为已通知
          const resultKey = this.getResultKey(result);
          this.notifiedResults.add(resultKey);
          this.processedNotifications.add(resultKey);
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
        
        // 从缓存和结果中移除
        this.resultCache.delete(id);
        
        // 从当前结果列表中移除
        const index = this.results.findIndex(r => r.id === id);
        if (index !== -1) {
          this.results.splice(index, 1);
          this.totalResults--;
        }
        
        // 如果当前页面没有结果且不是第一页，则返回上一页
        if (this.results.length === 0 && this.currentPage > 1) {
          this.currentPage--;
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
        
        // 更新详情对话框和缓存
        if (this.selectedResult && this.selectedResult.id === id) {
          this.selectedResult.is_verified = true;
        }
        
        // 更新缓存中的数据
        if (this.resultCache.has(id)) {
          const result = this.resultCache.get(id);
          result.is_verified = true;
          this.resultCache.set(id, result);
        }
        
        // 更新当前结果列表
        const resultIndex = this.results.findIndex(r => r.id === id);
        if (resultIndex !== -1) {
          this.results[resultIndex].is_verified = true;
        }
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
  position: relative;
}

.ws-status-indicator {
  position: absolute;
  right: 0;
  top: 0;
  display: flex;
  align-items: center;
}

.ws-status-tag {
  font-size: 12px;
  height: 22px;
  line-height: 20px;
  padding: 0 6px;
}
</style>