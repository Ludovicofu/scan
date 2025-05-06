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
      notificationThrottleTime: 2000, // 相同类型通知的最小间隔(ms)
      lastNotificationTime: {} // 记录每种类型通知的最后时间
    };
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

          // 添加事件监听器
          dataCollectionWS.addListener('scan_result', this.handleScanResult);
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          ElMessage.error('连接服务器失败，实时扫描结果将不可用');
        });
    },

    closeWebSocket() {
      // 移除事件监听器
      dataCollectionWS.removeListener('scan_result', this.handleScanResult);
    },

    // 处理扫描结果的逻辑
    handleScanResult(data) {
      // 检查消息格式
      if (!data || !data.data) {
        console.error("无效的扫描结果数据");
        return;
      }

      const resultData = data.data;

      // 确保资产主机字段存在
      this.ensureAssetHost(resultData);

      // 检查是否是当前显示的扫描类型
      if (resultData.scan_type !== this.currentScanType) {
        console.log(`跳过不匹配当前扫描类型的结果: ${resultData.scan_type} != ${this.currentScanType}`);
        return;
      }

      // 构建结果唯一标识 - 使用正确的资产显示值
      const resultId = resultData.id;
      const assetDisplay = resultData.asset_host || (typeof resultData.asset === 'string' ? resultData.asset : '未知资产');
      const resultKey = `${assetDisplay}-${resultData.module}-${resultData.description}-${resultData.rule_type}`;

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

        console.log("查询参数:", params);

        if (this.currentScanType === 'passive') {
          response = await infoCollectionAPI.getPassiveScanResults(params);
        } else {
          response = await infoCollectionAPI.getActiveScanResults(params);
        }

        // 处理API响应
        this.results = response.results || [];
        this.totalResults = response.count || 0;

        // 修复结果中可能缺失的asset_host字段
        this.results.forEach(result => {
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
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
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

.result-container {
  margin-top: 20px;
}

@media (max-width: 768px) {
  .scan-type-tabs {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>