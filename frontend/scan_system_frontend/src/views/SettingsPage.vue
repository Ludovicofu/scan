<template>
  <div class="settings-page">
    <h1>系统设置</h1>

    <el-card class="settings-card">
      <template #header>
        <span>代理设置</span>
      </template>
      <el-form :model="proxyForm" label-width="120px" :disabled="loading">
        <el-form-item label="使用代理">
          <el-switch v-model="proxyForm.use_proxy"></el-switch>
        </el-form-item>

        <el-form-item label="代理地址" v-if="proxyForm.use_proxy">
          <el-input v-model="proxyForm.proxy_address" placeholder="例如：http://localhost:7890"></el-input>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveProxySettings" :loading="saveProxyLoading">保存代理设置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="settings-card">
      <template #header>
        <span>跳过目标管理</span>
      </template>
      <div class="skip-targets">
        <div class="skip-targets-form">
          <el-form :model="skipTargetForm" :rules="skipTargetRules" ref="skipTargetForm" label-width="80px" :disabled="loading">
            <el-form-item label="目标" prop="target">
              <el-input v-model="skipTargetForm.target" placeholder="输入要跳过的域名或IP"></el-input>
            </el-form-item>

            <el-form-item label="描述" prop="description">
              <el-input v-model="skipTargetForm.description" placeholder="输入描述（可选）"></el-input>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="addSkipTarget" :loading="addSkipTargetLoading">添加</el-button>
            </el-form-item>
          </el-form>
        </div>

        <div class="skip-targets-list">
          <h3>跳过目标列表</h3>
          <el-table
            v-loading="skipTargetsLoading"
            :data="skipTargets"
            border
            style="width: 100%"
          >
            <el-table-column
              type="index"
              label="序号"
              width="60"
            ></el-table-column>

            <el-table-column
              prop="target"
              label="目标"
              width="250"
            ></el-table-column>

            <el-table-column
              prop="description"
              label="描述"
            ></el-table-column>

            <el-table-column
              fixed="right"
              label="操作"
              width="100"
            >
              <template #default="scope">
                <el-button
                  @click="deleteSkipTarget(scope.row.id)"
                  type="text"
                  size="small"
                  class="delete-btn"
                >
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>
    </el-card>

    <el-card class="settings-card">
      <template #header>
        <span>扫描选项</span>
      </template>
      <el-form :model="scanForm" label-width="180px" :disabled="loading">
        <el-form-item label="扫描超时时间（秒）">
          <el-input-number v-model="scanForm.scan_timeout" :min="1" :max="60"></el-input-number>
        </el-form-item>

        <el-form-item label="最大并发扫描数">
          <el-input-number v-model="scanForm.max_concurrent_scans" :min="1" :max="20"></el-input-number>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveScanSettings" :loading="saveScanLoading">保存扫描设置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="settings-card">
      <template #header>
        <span>系统状态</span>
      </template>
      <div class="system-status">
        <el-row :gutter="20">
          <el-col :span="8">
            <div class="status-item">
              <div class="status-title">Mitmproxy代理状态</div>
              <div class="status-value" :class="{'status-active': proxyStatus, 'status-inactive': !proxyStatus}">
                {{ proxyStatus ? '运行中' : '未运行' }}
              </div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="status-item">
              <div class="status-title">Django服务状态</div>
              <div class="status-value" :class="{'status-active': djangoStatus, 'status-inactive': !djangoStatus}">
                {{ djangoStatus ? '运行中' : '未运行' }}
              </div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="status-item">
              <div class="status-title">Redis服务状态</div>
              <div class="status-value" :class="{'status-active': redisStatus, 'status-inactive': !redisStatus}">
                {{ redisStatus ? '运行中' : '未运行' }}
              </div>
            </div>
          </el-col>
        </el-row>
      </div>
    </el-card>
  </div>
</template>

<script>
import { settingsAPI } from '@/services/api';
import { dataCollectionWS } from '@/services/websocket';
import { ElMessage, ElMessageBox } from 'element-plus';

export default {
  name: 'SettingsPage',
  data() {
    return {
      loading: false,

      // 代理设置
      proxyForm: {
        use_proxy: false,
        proxy_address: 'http://localhost:7890'
      },
      saveProxyLoading: false,

      // 跳过目标
      skipTargets: [],
      skipTargetsLoading: false,
      skipTargetForm: {
        target: '',
        description: ''
      },
      skipTargetRules: {
        target: [
          { required: true, message: '请输入要跳过的目标', trigger: 'blur' }
        ]
      },
      addSkipTargetLoading: false,

      // 扫描选项
      scanForm: {
        scan_timeout: 10,
        max_concurrent_scans: 5
      },
      saveScanLoading: false,

      // 系统状态
      proxyStatus: false,
      djangoStatus: true, // 如果页面加载成功，Django服务肯定是运行的
      redisStatus: false
    };
  },
  created() {
    this.initWebSocket();
    this.fetchSettings();
    this.fetchSkipTargets();
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
          dataCollectionWS.addListener('settings_update', this.handleSettingsUpdate);
          dataCollectionWS.addListener('skip_target_update', this.handleSkipTargetUpdate);
        })
        .catch(error => {
          console.error('连接WebSocket失败', error);
          this.redisStatus = false;
        });
    },
    closeWebSocket() {
      // 移除事件监听器
      dataCollectionWS.removeListener('settings_update', this.handleSettingsUpdate);
      dataCollectionWS.removeListener('skip_target_update', this.handleSkipTargetUpdate);
    },
    handleSettingsUpdate(data) {
      // 处理设置更新事件
      this.proxyForm.use_proxy = data.data.use_proxy;
      this.proxyForm.proxy_address = data.data.proxy_address;
      this.scanForm.scan_timeout = data.data.scan_timeout;
      this.scanForm.max_concurrent_scans = data.data.max_concurrent_scans;
    },
    handleSkipTargetUpdate(data) {
      // 处理跳过目标更新事件
      if (data.action === 'add') {
        // 重新获取跳过目标列表
        this.fetchSkipTargets();
      } else if (data.action === 'remove') {
        // 从列表中移除目标
        const index = this.skipTargets.findIndex(t => t.target === data.target);
        if (index >= 0) {
          this.skipTargets.splice(index, 1);
        }
      }
    },

    // 数据操作方法
    async fetchSettings() {
      this.loading = true;
      try {
        const response = await settingsAPI.getSettings();
        this.proxyForm.use_proxy = response.use_proxy;
        this.proxyForm.proxy_address = response.proxy_address;
        this.scanForm.scan_timeout = response.scan_timeout;
        this.scanForm.max_concurrent_scans = response.max_concurrent_scans;
      } catch (error) {
        console.error('获取系统设置失败', error);
        ElMessage.error('获取系统设置失败');
      } finally {
        this.loading = false;
      }
    },
    async saveProxySettings() {
      this.saveProxyLoading = true;
      try {
        const data = {
          use_proxy: this.proxyForm.use_proxy,
          proxy_address: this.proxyForm.proxy_address,
          scan_timeout: this.scanForm.scan_timeout,
          max_concurrent_scans: this.scanForm.max_concurrent_scans
        };
        await settingsAPI.updateSettings(data);
        ElMessage.success('代理设置保存成功');
      } catch (error) {
        console.error('保存代理设置失败', error);
        ElMessage.error('保存代理设置失败');
      } finally {
        this.saveProxyLoading = false;
      }
    },
    async saveScanSettings() {
      this.saveScanLoading = true;
      try {
        const data = {
          use_proxy: this.proxyForm.use_proxy,
          proxy_address: this.proxyForm.proxy_address,
          scan_timeout: this.scanForm.scan_timeout,
          max_concurrent_scans: this.scanForm.max_concurrent_scans
        };
        await settingsAPI.updateSettings(data);
        ElMessage.success('扫描设置保存成功');
      } catch (error) {
        console.error('保存扫描设置失败', error);
        ElMessage.error('保存扫描设置失败');
      } finally {
        this.saveScanLoading = false;
      }
    },
    async fetchSkipTargets() {
      this.skipTargetsLoading = true;
      try {
        const response = await settingsAPI.getSkipTargets();
        // 确保skipTargets始终是数组
        this.skipTargets = Array.isArray(response) ? response : [];
      } catch (error) {
        console.error('获取跳过目标失败', error);
        ElMessage.error('获取跳过目标失败');
        // 出错时设置为空数组
        this.skipTargets = [];
      } finally {
        this.skipTargetsLoading = false;
      }
    },
    async addSkipTarget() {
      try {
        await this.$refs.skipTargetForm.validate();

        this.addSkipTargetLoading = true;
        await settingsAPI.createSkipTarget({
          target: this.skipTargetForm.target,
          description: this.skipTargetForm.description
        });

        // 重置表单
        this.skipTargetForm.target = '';
        this.skipTargetForm.description = '';
        this.$refs.skipTargetForm.resetFields();

        // 刷新列表
        this.fetchSkipTargets();

        ElMessage.success('添加成功');
      } catch (error) {
        if (error !== false) {
          console.error('添加跳过目标失败', error);
          ElMessage.error('添加跳过目标失败');
        }
      } finally {
        this.addSkipTargetLoading = false;
      }
    },
    async deleteSkipTarget(id) {
      try {
        await ElMessageBox.confirm('确认删除该跳过目标?', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        });

        await settingsAPI.deleteSkipTarget(id);

        // 刷新列表
        this.fetchSkipTargets();

        ElMessage.success('删除成功');
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除跳过目标失败', error);
          ElMessage.error('删除跳过目标失败');
        }
      }
    },

    // 系统状态检测
    async checkSystemStatus() {
      // 检测mitmproxy状态
      try {
        // 这里使用一个简单的方式检测代理状态
        // 实际项目中可能需要更复杂的检测方式
        await fetch('http://localhost:8000/proxy/', { method: 'OPTIONS', timeout: 2000 });
        this.proxyStatus = true;
      } catch (error) {
        this.proxyStatus = false;
      }
    }
  }
};
</script>

<style scoped>
.settings-page {
  padding: 20px;
}

h1 {
  margin-bottom: 20px;
  font-size: 24px;
  color: #303133;
}

.settings-card {
  margin-bottom: 20px;
}

.skip-targets {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
}

.skip-targets-form {
  flex: 1;
  min-width: 300px;
}

.skip-targets-list {
  flex: 2;
  min-width: 400px;
}

.skip-targets-list h3 {
  margin-bottom: 15px;
  font-size: 16px;
  color: #303133;
}

.system-status {
  padding: 10px;
}

.status-item {
  padding: 15px;
  border-radius: 4px;
  background-color: #f9f9f9;
  text-align: center;
}

.status-title {
  font-size: 14px;
  color: #606266;
  margin-bottom: 10px;
}

.status-value {
  font-size: 16px;
  font-weight: bold;
}

.status-active {
  color: #67C23A;
}

.status-inactive {
  color: #F56C6C;
}

.delete-btn {
  color: #F56C6C;
}

.delete-btn:hover {
  color: #f78989;
}

@media (max-width: 768px) {
  .skip-targets {
    flex-direction: column;
  }
}
</style>