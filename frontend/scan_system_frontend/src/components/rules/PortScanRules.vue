// frontend/scan_system_frontend/src/components/rules/PortScanRules.vue
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

      <div class="port-rules-content">
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
          <div class="hint">常用端口示例：21(FTP), 22(SSH), 80(HTTP), 443(HTTPS), 3306(MySQL), 8080(HTTP代理)</div>
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
      try {
        // 获取网络模块的主动扫描规则
        const response = await rulesAPI.getInfoCollectionRulesByModuleAndType('network', 'active');

        // 找到规则类型为'port'的规则
        const portRules = response.filter(rule => rule.rule_type === 'port');

        if (portRules.length > 0) {
          this.portRule = portRules[0]; // 使用第一个端口扫描规则

          // 解析端口列表
          this.portList = this.parsePortsFromRule(this.portRule.match_values);
          this.portText = this.portList.join('\n'); // 转换为每行一个的文本
        } else {
          // 如果没有找到端口规则，初始化为空
          this.portList = [];
          this.portText = '';
        }
      } catch (error) {
        console.error('获取端口扫描规则失败', error);
        ElMessage.error('获取端口扫描规则失败');

        // 默认常用端口
        this.portList = ['80', '443', '8080', '3306', '22', '21'];
        this.portText = this.portList.join('\n');
      }
    },

    parsePortsFromRule(matchValues) {
      // 解析规则的匹配值，返回端口列表
      if (!matchValues) return [];

      // 解析文本中的端口号
      return matchValues.split(/[\n,]/).map(port => port.trim()).filter(port => port);
    },

    editPortRules() {
      // 进入编辑模式
      this.isEditing = true;
    },

    async savePortRules() {
      try {
        // 将文本框中的内容解析为端口列表
        const ports = this.portText.split('\n').map(port => port.trim()).filter(port => {
          // 验证是否为有效的端口号（1-65535）
          const portNum = parseInt(port);
          return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
        });

        if (ports.length === 0) {
          ElMessage.warning('请输入至少一个有效的端口号');
          return;
        }

        // 准备规则数据
        const ruleData = {
          module: 'network',
          scan_type: 'active',
          description: '端口扫描',
          rule_type: 'port',
          match_values: ports.join('\n'),
          behaviors: '',
          is_enabled: true
        };

        if (this.portRule) {
          // 如果已有规则，则更新
          await rulesAPI.updateInfoCollectionRule(this.portRule.id, ruleData);
          ElMessage.success('端口规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createInfoCollectionRule(ruleData);
          this.portRule = response;
          ElMessage.success('端口规则创建成功');
        }

        // 更新端口列表
        this.portList = ports;
        this.isEditing = false;
      } catch (error) {
        console.error('保存端口规则失败', error);
        ElMessage.error('保存端口规则失败');
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
</style>