<template>
  <div class="info-results-page">
    <h1>信息收集结果</h1>

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

      <!-- 仅保留WebSocket状态指示 -->
      <div class="ws-status-area">
        <el-tag
          :type="isWebSocketConnected ? 'success' : 'danger'"
          size="small"
          class="ws-status-tag"
        >
          {{ isWebSocketConnected ? 'WebSocket已连接' : 'WebSocket未连接' }}
        </el-tag>
      </div>
    </div>

    <!-- 根据当前扫描类型显示对应的结果组件 -->
    <div class="result-container">
      <!-- 被动扫描结果 -->
      <PassiveScanResults
        v-if="currentScanType === 'passive'"
        :results="results"
        :loading="loading"
        :current-page="currentPage"
        :page-size="pageSize"
        :total="totalResults"
        @size-change="handleSizeChange"
        @current-change="handlePageChange"
        @view-detail="showDetail"
        @delete-result="deleteResult"
      />

      <!-- 主动扫描结果 -->
      <ActiveScanResults
        v-if="currentScanType === 'active'"
        :results="results"
        :loading="loading"
        :current-page="currentPage"
        :page-size="pageSize"
        :total="totalResults"
        @size-change="handleSizeChange"
        @current-change="handlePageChange"
        @view-detail="showDetail"
        @delete-result="deleteResult"
      />
    </div>

    <!-- 结果详情对话框 -->
    <InfoResultDetailDialog
      :visible="detailDialogVisible"
      :result="selectedResult"
      @close="detailDialogVisible = false"
    />
  </div>
</template>

<script>
import ResultFilters from '@/components/common/ResultFilters.vue';
import PassiveScanResults from '@/components/info/PassiveScanResults.vue';
import ActiveScanResults from '@/components/info/ActiveScanResults.vue';
import InfoResultDetailDialog from '@/components/info/InfoResultDetailDialog.vue';
import { infoCollectionAPI } from '@/services/api';
import { dataCollectionWS } from '@/services/websocket';
import { ElMessage, ElNotification, ElMessageBox } from 'element-plus';

export default {
  name: 'InfoResultsPage',
  components: {
    ResultFilters,
    PassiveScanResults,
    ActiveScanResults,
    InfoResultDetailDialog
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
      currentScanType: 'passive',

      // 详情对话框
      detailDialogVisible: false,
      selectedResult: null,

      // 去重相关
      resultCache: new Map(), // 用于跟踪已经显示的结果，键为 ID
      notificationCache: new Map(), // 用于跟踪已经通知的结果，键为 asset-module-description-rule_type
      resultIdSet: new Set(), // 用于跟踪已显示的结果ID

      // 通知节流控制
      notificationThrottleTime: 5000, // 增加到5秒 - 相同类型通知的最小间隔(ms)
      lastNotificationTime: {}, // 记录每种类型通知的最后时间

      // WebSocket状态
      isWebSocketConnected: false,

      // WebSocket重连尝试计时器
      wsReconnectTimer: null,

      // 限制扫描结果更新频率
      resultUpdateThrottleTime: 3000, // 新增，3秒内只处理一次同类型结果
      lastResultUpdateTime: {} // 新增，记录上次结果更新时间
    };
  },
  created() {
    this.initWebSocket();
    this.fetchResults();

    // 从 localStorage 恢复缓存数据
    this.loadCacheFromStorage();

    // 定期检查WebSocket连接状态
    this.startWebSocketStatusCheck();

    // 监听页面可见性变化
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
  },
  beforeUnmount() {
    this.closeWebSocket();
    this.stopWebSocketStatusCheck();

    // 移除页面可见性变化监听
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);

    // 保存缓存数据到 localStorage
    this.saveCacheToStorage();
  },
  methods: {
    // 处理页面可见性变化
    handleVisibilityChange() {
      if (document.visibilityState === 'visible') {
        // 页面变为可见时，检查WebSocket连接状态
        console.log('页面变为可见，检查WebSocket连接状态');
        this.checkWebSocketStatus();

        // 刷新结果
        this.fetchResults();
      }
    },

    // 检查WebSocket连接状态
    checkWebSocketStatus() {
      // 检查WebSocket是否连接
      const wasConnected = this.isWebSocketConnected;
      this.isWebSocketConnected = dataCollectionWS.isConnected;

      // 如果状态由已连接变为未连接，尝试重连
      if (wasConnected && !this.isWebSocketConnected) {
        console.log('检测到WebSocket连接断开，尝试重连');
        this.reconnectWebSocket();
      }

      // 如果连接正常，尝试发送PING消息来验证连接
      if (this.isWebSocketConnected) {
        try {
          dataCollectionWS.send({ type: 'ping', timestamp: Date.now() });
          console.log('已发送PING消息以验证连接');
        } catch (error) {
          console.error('PING消息发送失败，连接可能已断开', error);
          this.isWebSocketConnected = false;
          this.reconnectWebSocket();
        }
      }
    },

    // 重连WebSocket
    reconnectWebSocket() {
      // 重置WebSocket客户端
      dataCollectionWS.disconnect();

      // 延迟1秒后重连
      setTimeout(() => {
        this.initWebSocket();
      }, 1000);
    },

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

    // 启动WebSocket状态检查
    startWebSocketStatusCheck() {
      // 清除可能存在的旧计时器
      this.stopWebSocketStatusCheck();

      // 创建15秒间隔的检查
      this.wsStatusCheckTimer = setInterval(() => {
        // 更新WebSocket连接状态
        this.isWebSocketConnected = dataCollectionWS.isConnected;

        // 如果检测到连接断开，尝试重新连接
        if (!this.isWebSocketConnected && !this.wsReconnectTimer) {
          console.log('检测到WebSocket连接断开，准备重新连接...');
          this.wsReconnectTimer = setTimeout(() => {
            this.wsReconnectTimer = null;
            this.initWebSocket();
          }, 3000); // 3秒后重连
        }
      }, 15000); // 每15秒检查一次
    },

    // 停止WebSocket状态检查
    stopWebSocketStatusCheck() {
      if (this.wsStatusCheckTimer) {
        clearInterval(this.wsStatusCheckTimer);
        this.wsStatusCheckTimer = null;
      }

      if (this.wsReconnectTimer) {
        clearTimeout(this.wsReconnectTimer);
        this.wsReconnectTimer = null;
      }
    },

    // WebSocket相关方法
    initWebSocket() {
      // 连接WebSocket
      console.log("正在连接WebSocket...");
      dataCollectionWS.connect('ws://localhost:8000/ws/data_collection/')
        .then(() => {
          console.log("WebSocket连接成功!");
          this.isWebSocketConnected = true;

          // 添加事件监听器
          dataCollectionWS.addListener('scan_result', this.handleScanResult);
          dataCollectionWS.addListener('scan_progress', this.handleScanProgress);

          // 自动刷新结果
          this.fetchResults();
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          this.isWebSocketConnected = false;
        });
    },

    closeWebSocket() {
      // 移除事件监听器
      dataCollectionWS.removeListener('scan_result', this.handleScanResult);
      dataCollectionWS.removeListener('scan_progress', this.handleScanProgress);
      this.isWebSocketConnected = false;
    },

    // 处理扫描进度的逻辑
    handleScanProgress(data) {
      if (!data || !data.data) return;

      const progressData = data.data;
      const now = Date.now();
      const lastTime = this.lastNotificationTime['progress'] || 0;

      // 对扫描进度消息进行节流
      if (now - lastTime < 5000) { // 5秒内不重复通知相同类型进度
        return;
      }

      // 更新最后通知时间
      this.lastNotificationTime['progress'] = now;

      // 根据不同的状态显示不同的通知
      switch(progressData.status) {
        case 'scanning':
          // 扫描中状态仅在控制台输出，不弹出通知
          console.log('扫描中:', progressData.message || '正在进行扫描...');
          break;

        case 'completed':
          ElNotification({
            title: '扫描完成',
            message: progressData.message || '扫描已完成',
            type: 'success',
            duration: 3000
          });

          // 扫描完成后刷新结果列表
          setTimeout(() => {
            this.fetchResults();
          }, 500);  // 减少到500ms以更快地获取结果
          break;

        case 'error':
          ElNotification({
            title: '扫描错误',
            message: progressData.message || '扫描过程中发生错误',
            type: 'error',
            duration: 5000
          });
          break;
      }
    },

    // 处理扫描结果的逻辑
    handleScanResult(data) {
      // 检查消息格式
      if (!data || !data.data) {
        return;
      }

      const resultData = data.data;

      // 确保扫描日期字段存在并有效
      this.ensureScanDate(resultData);

      // 确保资产主机字段存在
      this.ensureAssetHost(resultData);

      // 检查是否是当前显示的扫描类型
      if (resultData.scan_type !== this.currentScanType) {
        return;
      }

      // 构建结果唯一标识
      const resultId = resultData.id;
      const assetDisplay = resultData.asset_host || (typeof resultData.asset === 'string' ? resultData.asset : '未知资产');
      const resultKey = `${assetDisplay}-${resultData.module}-${resultData.description}-${resultData.rule_type}`;

      // 检查结果ID是否已存在（如果有ID）
      if (resultId && this.resultIdSet.has(resultId)) {
        return;
      }

      // 检查结果唯一标识是否已存在于缓存中
      if (this.notificationCache.has(resultKey)) {
        return;
      }

      // 限制结果更新频率
      const now = Date.now();
      const moduleKey = resultData.module || 'unknown';
      const lastUpdateTime = this.lastResultUpdateTime[moduleKey] || 0;

      if (now - lastUpdateTime < this.resultUpdateThrottleTime) {
        console.log(`跳过短时间内的${moduleKey}类型结果更新`);
        return;
      }

      // 更新该模块的最后更新时间
      this.lastResultUpdateTime[moduleKey] = now;

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

      // 插入到结果列表头部
      this.results.unshift(resultData);
      this.totalResults++;

      // 构建通知消息并显示
      this.showResultNotification(resultData);
    },

    // 确保scan_date字段存在并有效
    ensureScanDate(result) {
      if (!result) return;

      // 如果没有scan_date字段或字段值无效，添加当前时间
      if (!result.scan_date || result.scan_date === 'null' || result.scan_date === 'undefined') {
        result.scan_date = new Date().toISOString();
        console.log('为结果添加当前时间作为扫描日期');
      }
    },

    // 添加一个专门的通知显示方法
    showResultNotification(resultData) {
      // 获取当前时间戳
      const now = Date.now();

      // 节流通知显示
      const moduleKey = resultData.module || 'unknown';
      const typeKey = resultData.is_port_scan ? 'port-scan' : moduleKey;
      const lastTime = this.lastNotificationTime[typeKey] || 0;

      if (now - lastTime < this.notificationThrottleTime) {
        console.log(`跳过${typeKey}类型的通知，间隔过短`);
        return;
      }

      // 更新最后通知时间
      this.lastNotificationTime[typeKey] = now;

      // 确定通知类型
      let notificationType = 'info';
      let notificationTitle = '';
      let notificationMessage = '';

      // 获取资产名称
      const assetName = this.getAssetDisplay(resultData);

      // 根据结果类型设置通知内容
      if (resultData.rule_type === 'port' || resultData.is_port_scan) {
        // 端口扫描结果
        notificationType = 'warning';
        notificationTitle = '端口扫描结果';

        // 使用formatPortNumbers只显示端口号
        const portNumbers = this.formatPortNumbers(resultData.match_value);
        notificationMessage = `资产 ${assetName} 发现开放端口: ${portNumbers}`;
      } else {
        // 根据模块设置不同的通知
        switch(resultData.module) {
          case 'network':
            notificationTitle = '网络信息';
            notificationMessage = `资产 ${assetName} 发现网络信息: ${resultData.description}`;
            break;
          case 'os':
            notificationTitle = '操作系统信息';
            notificationMessage = `资产 ${assetName} 发现操作系统信息: ${resultData.description}`;
            break;
          case 'component':
            notificationTitle = '组件与服务信息';
            notificationMessage = `资产 ${assetName} 发现组件信息: ${resultData.description}`;
            break;
          default:
            notificationTitle = '扫描结果';
            notificationMessage = `资产 ${assetName} 发现新结果: ${resultData.description}`;
        }
      }

      // 显示通知
      ElNotification({
        title: notificationTitle,
        message: notificationMessage,
        type: notificationType,
        duration: 3000
      });
    },

    // 确保资产主机字段存在并有正确的值
    ensureAssetHost(result) {
      if (!result) return;

      // 如果没有asset_host字段，尝试从asset获取
      if (!result.asset_host && result.asset) {
        // 如果asset是字符串类型且不是纯数字ID
        if (typeof result.asset === 'string' && !result.asset.match(/^\d+$/)) {
          result.asset_host = result.asset;
        }
        // 如果asset是对象类型且有host属性
        else if (typeof result.asset === 'object' && result.asset.host) {
          result.asset_host = result.asset.host;
        }
      }

      // 确保最终有一个有效的资产显示值
      if (!result.asset_host && typeof result.asset === 'string') {
        result.asset_host = result.asset;
      } else if (!result.asset_host) {
        // 如果都没有，设置为默认值，但这不应该发生
        console.warn('无法确定资产显示值，使用默认值');
        result.asset_host = '未知资产';
      }
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
          response = await infoCollectionAPI.getPassiveScanResults(params);
        } else {
          response = await infoCollectionAPI.getActiveScanResults(params);
        }

        // 处理API响应
        this.results = response.results || [];
        this.totalResults = response.count || 0;

        // 确保每个结果都有扫描日期和资产主机字段
        this.results.forEach(result => {
          this.ensureScanDate(result);
          this.ensureAssetHost(result);
        });

        // 更新已处理的结果IDs
        this.results.forEach(result => {
          if (result.id) {
            this.resultIdSet.add(result.id);
          }
          // 更新通知缓存
          const resultKey = `${this.getAssetDisplay(result)}-${result.module}-${result.description}-${result.rule_type}`;
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
          const resultKey = `${this.getAssetDisplay(result)}-${result.module}-${result.description}-${result.rule_type}`;
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

    // 获取资产显示文本
    getAssetDisplay(row) {
      if (!row) return '未知资产';

      // 优先级：asset_host > asset（如果asset是字符串） > '未知资产'
      if (row.asset_host) {
        return row.asset_host;
      } else if (row.asset && typeof row.asset === 'string' && !row.asset.match(/^\d+$/)) {
        return row.asset;
      } else {
        return '未知资产';
      }
    },

    // 提取端口号
    formatPortNumbers(matchValue) {
      if (!matchValue) return '';

      // 提取所有端口号
      const ports = [];
      const lines = matchValue.split('\n');

      for (const line of lines) {
        if (line && line.includes(':')) {
          const port = line.split(':', 1)[0].trim();
          if (port && !isNaN(port)) {
            ports.push(port);
          }
        }
      }

      // 返回逗号分隔的端口号列表
      return ports.join(', ');
    },

    // 工具方法
    formatDate(dateString) {
      if (!dateString) return '';

      try {
        const date = new Date(dateString);
        // 检查是否是有效日期
        if (isNaN(date.getTime())) {
          console.warn('无效的日期:', dateString);
          return '日期无效';
        }

        return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
      } catch (error) {
        console.error('日期格式化错误:', error, dateString);
        return '日期错误';
      }
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
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.ws-status-area {
  display: flex;
  align-items: center;
}

.ws-status-tag {
  margin-left: 8px;
}

.result-container {
  margin-top: 20px;
}

@media (max-width: 768px) {
  .scan-type-tabs {
    flex-direction: column;
    align-items: flex-start;
  }

  .ws-status-area {
    margin-top: 10px;
    width: 100%;
    justify-content: flex-end;
  }
}
</style>