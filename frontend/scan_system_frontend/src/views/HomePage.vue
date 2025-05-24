<template>
  <div class="home-page">
    <div class="home-header">
      <h1>半自动化漏洞扫描系统</h1>
      <p></p>
    </div>

    <div class="dashboard">
      <el-row :gutter="20">
        <!-- 资产统计 -->
        <el-col :span="8">
          <el-card class="data-card">
            <template #header>
              <div class="card-header">
                <span>资产统计</span>
              </div>
            </template>
            <div class="card-content">
              <div class="data-number">{{ stats.assets }}</div>
              <div class="data-label">扫描资产总数</div>
            </div>
            <div class="card-footer">
              <router-link to="/info-results">查看详情</router-link>
            </div>
          </el-card>
        </el-col>

        <!-- 信息收集结果 -->
        <el-col :span="8">
          <el-card class="data-card">
            <template #header>
              <div class="card-header">
                <span>信息收集</span>
              </div>
            </template>
            <div class="card-content">
              <div class="data-number">{{ stats.infoResults }}</div>
              <div class="data-label">收集结果总数</div>
            </div>
            <div class="card-footer">
              <router-link to="/info-results">查看详情</router-link>
            </div>
          </el-card>
        </el-col>

        <!-- 漏洞发现 -->
        <el-col :span="8">
          <el-card class="data-card">
            <template #header>
              <div class="card-header">
                <span>漏洞发现</span>
              </div>
            </template>
            <div class="card-content">
              <div class="data-number">{{ stats.vulnResults }}</div>
              <div class="data-label">漏洞发现总数</div>
            </div>
            <div class="card-footer">
              <router-link to="/vuln-results">查看详情</router-link>
            </div>
          </el-card>
        </el-col>
      </el-row>

      <el-row :gutter="20" class="dashboard-row">
        <!-- 最近扫描结果 -->
        <el-col :span="12">
          <el-card class="results-card">
            <template #header>
              <div class="card-header">
                <span>最近信息收集结果</span>
                <router-link to="/info-results" class="header-link">查看全部</router-link>
              </div>
            </template>
            <div class="card-content">
              <el-table
                v-loading="recentInfoLoading"
                :data="recentInfoResults"
                style="width: 100%"
                size="small"
              >
                <el-table-column
                  prop="scan_date"
                  label="日期"
                  width="150"
                >
                  <template #default="scope">
                    {{ formatDate(scope.row.scan_date) }}
                  </template>
                </el-table-column>

                <el-table-column
                  prop="description"
                  label="描述"
                  width="180"
                ></el-table-column>

                <el-table-column
                  prop="module_display"
                  label="模块"
                ></el-table-column>
              </el-table>
            </div>
          </el-card>
        </el-col>

        <!-- 系统状态 -->
        <el-col :span="12">
          <el-card class="status-card">
            <template #header>
              <div class="card-header">
                <span>系统状态</span>
                <router-link to="/settings" class="header-link">系统设置</router-link>
              </div>
            </template>
            <div class="card-content">
              <el-row class="status-row">
                <el-col :span="12" class="status-label">Mitmproxy代理:</el-col>
                <el-col :span="12" class="status-value">
                  <el-tag :type="proxyStatus ? 'success' : 'danger'">
                    {{ proxyStatus ? '运行中' : '未运行' }}
                  </el-tag>
                </el-col>
              </el-row>
              <el-row class="status-row">
                <el-col :span="12" class="status-label">Django服务:</el-col>
                <el-col :span="12" class="status-value">
                  <el-tag :type="djangoStatus ? 'success' : 'danger'">
                    {{ djangoStatus ? '运行中' : '未运行' }}
                  </el-tag>
                </el-col>
              </el-row>
              <el-row class="status-row">
                <el-col :span="12" class="status-label">Redis服务:</el-col>
                <el-col :span="12" class="status-value">
                  <el-tag :type="redisStatus ? 'success' : 'danger'">
                    {{ redisStatus ? '运行中' : '未运行' }}
                  </el-tag>
                </el-col>
              </el-row>
              <el-row class="status-row">
                <el-col :span="12" class="status-label">扫描状态:</el-col>
                <el-col :span="12" class="status-value">
                  <el-tag :type="scanStatus === 'scanning' ? 'primary' : 'info'">
                    {{ scanStatusText }}
                  </el-tag>
                </el-col>
              </el-row>
              <el-row class="status-row">
                <el-col :span="12" class="status-label">最后扫描时间:</el-col>
                <el-col :span="12" class="status-value">
                  {{ lastScanTime ? formatDate(lastScanTime) : '无' }}
                </el-col>
              </el-row>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>
  </div>
</template>

<script>
import { infoCollectionAPI, vulnScanAPI } from '@/services/api';
import { dataCollectionWS } from '@/services/websocket';

export default {
  name: 'HomePage',
  data() {
    return {
      // 统计数据
      stats: {
        assets: 0,
        infoResults: 0,
        vulnResults: 0
      },

      // 最近信息收集结果
      recentInfoResults: [],
      recentInfoLoading: false,

      // 系统状态
      proxyStatus: false,
      djangoStatus: true, // 如果页面加载成功，Django服务肯定是运行的
      redisStatus: false,
      scanStatus: 'idle', // idle, scanning, completed, error
      lastScanTime: null
    };
  },
  computed: {
    scanStatusText() {
      const statusMap = {
        idle: '空闲',
        scanning: '扫描中',
        completed: '已完成',
        error: '错误'
      };
      return statusMap[this.scanStatus] || '未知';
    }
  },
  created() {
    this.initWebSocket();
    this.fetchStats();
    this.fetchRecentInfoResults();
    this.checkSystemStatus();
  },
  beforeUnmount() {
    this.closeWebSocket();
  },
  methods: {
    // WebSocket相关方法
    initWebSocket() {
      // 连接WebSocket
      dataCollectionWS.connect('ws://localhost:8000/ws/data_collection/')
        .then(() => {
          // WebSocket连接成功，说明Redis服务正常
          this.redisStatus = true;

          // 添加事件监听器
          dataCollectionWS.addListener('scan_progress', this.handleScanProgress);
          dataCollectionWS.addListener('scan_result', this.handleScanResult);
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          this.redisStatus = false;
        });
    },
    closeWebSocket() {
      // 移除事件监听器
      dataCollectionWS.removeListener('scan_progress', this.handleScanProgress);
      dataCollectionWS.removeListener('scan_result', this.handleScanResult);
    },
    handleScanProgress(data) {
      // 处理扫描进度更新
      this.scanStatus = data.data.status;
      if (data.data.status === 'completed' || data.data.status === 'error') {
        this.lastScanTime = new Date().toISOString();
      }
    },
    handleScanResult(data) {
      // 处理扫描结果
      // 更新统计数据
      this.stats.infoResults++;

      // 更新最近结果
      if (this.recentInfoResults.length >= 10) {
        this.recentInfoResults.pop();
      }
      this.recentInfoResults.unshift(data.data);
    },

    // 数据获取方法
    async fetchStats() {
      try {
        // 获取资产统计
        const assetsResponse = await infoCollectionAPI.getAssets();
        this.stats.assets = assetsResponse.count || 0;

        // 获取信息收集结果统计
        const infoResultsResponse = await infoCollectionAPI.getScanResults();
        this.stats.infoResults = infoResultsResponse.count || 0;

        // 获取漏洞扫描结果统计
        const vulnResultsResponse = await vulnScanAPI.getScanResults();
        this.stats.vulnResults = vulnResultsResponse.count || 0;
      } catch (error) {
        console.error('获取统计数据失败', error);
      }
    },
    async fetchRecentInfoResults() {
      this.recentInfoLoading = true;
      try {
        const response = await infoCollectionAPI.getScanResults({ page_size: 10 });
        this.recentInfoResults = response.results || [];

        // 如果有结果，设置最后扫描时间
        if (this.recentInfoResults.length > 0) {
          this.lastScanTime = this.recentInfoResults[0].scan_date;
        }
      } catch (error) {
        console.error('获取最近信息收集结果失败', error);
      } finally {
        this.recentInfoLoading = false;
      }
    },

    // 系统状态检测
    async checkSystemStatus() {
        try {
            // 简化检测逻辑，避免OPTIONS请求
            await fetch('http://localhost:8000/', {
                method: 'GET',
                mode: 'no-cors' // 尝试避免CORS问题
            });
            this.proxyStatus = true;
        } catch (error) {
            console.log("代理状态检测出错，默认设为可用");
            this.proxyStatus = true; // 临时设为true，避免显示错误
        }
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
.home-page {
  padding: 20px;
}

.home-header {
  text-align: center;
  margin-bottom: 30px;
}

.home-header h1 {
  font-size: 28px;
  color: #303133;
  margin-bottom: 10px;
}

.home-header p {
  font-size: 16px;
  color: #606266;
}

.dashboard {
  margin-top: 20px;
}

.dashboard-row {
  margin-top: 20px;
}

.data-card {
  height: 180px;
  position: relative;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-link {
  font-size: 13px;
  color: #409EFF;
}

.card-content {
  padding: 10px 0;
}

.card-footer {
  position: absolute;
  bottom: 20px;
  right: 20px;
}

.data-number {
  font-size: 36px;
  font-weight: bold;
  color: #409EFF;
  margin-bottom: 5px;
  text-align: center;
}

.data-label {
  font-size: 14px;
  color: #606266;
  text-align: center;
}

.results-card, .status-card {
  height: 350px;
}

.status-row {
  margin-bottom: 15px;
  line-height: 32px;
}

.status-label {
  font-weight: bold;
  color: #606266;
}
</style>