<template>
  <div class="port-scan-rules">
    <h3>端口扫描设置</h3>
    <div class="port-rules-container">
      <div class="rules-header">
        <div class="rule-info">
          <span class="rule-title">要扫描的端口列表</span>
          <span class="rule-desc">添加需要扫描的目标端口</span>
        </div>
        <div class="rule-actions">
          <el-button
            type="primary"
            size="small"
            @click="editPortRules"
            v-if="!isEditing">
            修改
          </el-button>
          <template v-else>
            <el-button
              type="success"
              size="small"
              @click="savePortRules">
              保存
            </el-button>
            <el-button
              type="info"
              size="small"
              @click="cancelEdit">
              取消
            </el-button>
          </template>
        </div>
      </div>

      <div v-if="isLoading" class="loading-state">
        <el-skeleton :rows="3" animated />
      </div>
      <div v-else-if="loadError" class="error-state">
        <el-alert
          title="加载端口规则失败"
          type="error"
          description="使用默认端口配置"
          :closable="false"
          show-icon
        />
      </div>

      <div v-else class="port-rules-content">
        <div v-if="!isEditing" class="port-list">
          <div v-for="(port, index) in portList" :key="index" class="port-item">
            {{ port }}
          </div>
          <div v-if="portList.length === 0" class="no-port">
            没有配置端口，点击"修改"添加扫描端口
          </div>
        </div>
        <div v-else class="port-edit">
          <el-input
            type="textarea"
            v-model="portText"
            :rows="8"
            placeholder="请输入要扫描的端口，每行一个端口号"
          ></el-input>
          <div class="hint">
            常用端口示例：21(FTP), 22(SSH), 80(HTTP), 443(HTTPS), 3306(MySQL), 8080(HTTP代理)
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { rulesAPI } from '@/services/api';
import { ElMessage } from 'element-plus';

export default {
  name: 'PortScanRules',
  data() {
    return {
      isEditing: false,
      isLoading: false,
      loadError: false,
      portList: [],
      portText: '',
      portRule: null // 存储端口规则对象
    };
  },
  created() {
    this.fetchPortRules();
  },
  methods: {
    async fetchPortRules() {
      this.isLoading = true;
      this.loadError = false;

      try {
        console.log("开始获取端口扫描规则");

        // 获取所有信息收集规则
        const response = await rulesAPI.getInfoCollectionRules();
        console.log("获取规则API响应:", response);

        // 检查响应格式
        if (!response) {
          console.error("API 返回空响应");
          throw new Error("API 返回空响应");
        }

        // 从结果中过滤出网络模块的端口扫描规则
        let rules = [];
        if (Array.isArray(response)) {
          rules = response;
        } else if (response && Array.isArray(response.results)) {
          rules = response.results;
        } else {
          console.warn("意外的响应格式:", response);
          rules = [];
        }

        console.log("过滤前的规则数:", rules.length);

        // 找到网络模块的端口扫描规则
        const portRules = rules.filter(rule => {
          const isPortRule = rule &&
                           rule.module === 'network' &&
                           rule.rule_type === 'port' &&
                           rule.scan_type === 'active';
          console.log(`检查规则 ${rule ? rule.id : 'undefined'}: ${isPortRule ? '匹配' : '不匹配'}`);
          return isPortRule;
        });

        console.log("过滤后的端口扫描规则:", portRules);

        if (portRules.length > 0) {
          this.portRule = portRules[0]; // 使用第一个端口扫描规则
          console.log("找到端口规则:", this.portRule);

          // 解析端口列表
          this.portList = this.parsePortsFromRule(this.portRule.match_values);
          this.portText = this.portList.join('\n'); // 转换为每行一个的文本
          console.log("解析的端口列表:", this.portList);
        } else {
          console.log("未找到端口规则，使用默认值");
          // 如果没有找到端口规则，使用默认值
          this.portList = ['80', '443', '8080', '3306', '22', '21'];
          this.portText = this.portList.join('\n');
          this.portRule = null;

          // 尝试创建默认规则
          await this.createDefaultPortRule();
        }
      } catch (error) {
        console.error('获取端口扫描规则失败', error);
        this.loadError = true;

        // 使用默认常用端口
        this.portList = ['80', '443', '8080', '3306', '22', '21'];
        this.portText = this.portList.join('\n');

        ElMessage.error('获取端口扫描规则失败，使用默认配置');
      } finally {
        this.isLoading = false;
      }
    },

    async createDefaultPortRule() {
      try {
        console.log("创建默认端口扫描规则");

        // 准备规则数据
        const ruleData = {
          module: 'network',
          scan_type: 'active',
          description: '端口扫描',
          rule_type: 'port',
          match_values: '80\n443\n8080\n3306\n22\n21',
          behaviors: '',
          is_enabled: true
        };

        // 创建规则
        const response = await rulesAPI.createInfoCollectionRule(ruleData);
        console.log("默认规则创建成功:", response);
        this.portRule = response;

        ElMessage.success('已创建默认端口扫描规则');

        return response;
      } catch (error) {
        console.error('创建默认端口规则失败', error);
        return null;
      }
    },

    parsePortsFromRule(matchValues) {
      // 解析规则的匹配值，返回端口列表
      if (!matchValues) return [];

      // 解析文本中的端口号
      return matchValues.split(/[\n,\s]/).map(port => port.trim()).filter(port => port);
    },

    editPortRules() {
      // 进入编辑模式
      this.isEditing = true;
    },

    async savePortRules() {
      try {
        // 将文本框中的内容解析为端口列表
        const ports = this.portText.split('\n')
          .map(port => port.trim())
          .filter(port => {
            if (!port) return false;
            // 验证是否为有效的端口号（1-65535）
            const portNum = parseInt(port);
            return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
          });

        // 准备规则数据 - 允许为空
        const ruleData = {
          module: 'network',
          scan_type: 'active',
          description: '端口扫描',
          rule_type: 'port',
          match_values: ports.join('\n'),
          behaviors: '',
          is_enabled: true
        };

        console.log("准备保存端口规则数据:", ruleData);

        if (this.portRule && this.portRule.id) {
          // 如果已有规则，则更新
          console.log("更新规则ID:", this.portRule.id);
          await rulesAPI.updateInfoCollectionRule(this.portRule.id, ruleData);
          ElMessage.success(ports.length > 0 ? '端口规则更新成功' : '已清空所有端口');
        } else {
          // 如果没有规则，则创建
          console.log("创建新规则");
          const response = await rulesAPI.createInfoCollectionRule(ruleData);
          this.portRule = response;
          ElMessage.success(ports.length > 0 ? '端口规则创建成功' : '已创建空端口规则');
        }

        // 更新端口列表
        this.portList = ports;
        this.isEditing = false;
      } catch (error) {
        console.error('保存端口规则失败', error);
        ElMessage.error('保存端口规则失败: ' + error.message);
      }
    },

    cancelEdit() {
      // 取消编辑，恢复原始文本
      this.portText = this.portList.join('\n');
      this.isEditing = false;
    }
  }
};
</script>

<style scoped>
.port-scan-rules {
  margin-bottom: 30px;
}

.port-scan-rules h3 {
  margin-bottom: 15px;
  font-size: 18px;
  color: #303133;
  padding-left: 10px;
  border-left: 4px solid #409EFF;
}

.port-rules-container {
  background-color: #f5f7fa;
  border-radius: 4px;
  padding: 16px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}

.rules-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.rule-title {
  font-size: 16px;
  font-weight: bold;
  margin-right: 10px;
}

.rule-desc {
  font-size: 12px;
  color: #909399;
}

.port-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  min-height: 50px;
}

.port-item {
  background-color: #ecf5ff;
  color: #409eff;
  padding: 5px 10px;
  border-radius: 4px;
  font-family: monospace;
}

.no-port {
  color: #909399;
  font-style: italic;
}

.port-edit {
  margin-top: 10px;
}

.hint {
  margin-top: 5px;
  font-size: 12px;
  color: #909399;
}

.loading-state {
  padding: 20px 0;
}

.error-state {
  margin: 20px 0;
}
</style>