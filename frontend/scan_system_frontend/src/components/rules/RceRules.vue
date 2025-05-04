<!-- frontend/scan_system_frontend/src/components/rules/RceRules.vue -->
<template>
  <div class="rce-rules">
    <h3>命令/代码执行扫描设置</h3>
    <div class="rules-container">
      <!-- RCE载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">命令/代码执行载荷</span>
            <span class="rule-desc">添加用于检测命令执行和代码执行漏洞的测试载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editPayloads"
              v-if="!isEditingPayloads">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="savePayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditPayloads">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingPayloads" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadPayloadsFailed" class="error-state">
          <el-alert
            title="加载命令/代码执行规则失败"
            type="error"
            description="请添加规则"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingPayloads" class="payloads-list">
            <div v-for="(payload, index) in payloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="payloads.length === 0" class="no-payload">
              没有配置命令/代码执行载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="payloadsText"
              :rows="8"
              placeholder="请输入命令/代码执行载荷，每行一个"
            ></el-input>
            <div class="hint">
              <h4>命令执行载荷示例：</h4>
              <p>| id</p>
              <p>; cat /etc/passwd</p>
              <p>&& whoami</p>
              <p>|echo rce_test_cmd</p>
              <h4>代码执行载荷示例：</h4>
              <p>${7*7}</p>
              <p>${print('rce_test_code')}</p>
              <p>{{7*7}}</p>
              <p>{% import os %}</p>
              <p>eval('print("code_exec_test")')</p>
            </div>
          </div>
        </div>
      </div>

      <!-- RCE匹配模式 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">执行结果匹配模式</span>
            <span class="rule-desc">添加用于检测命令/代码执行成功的匹配模式</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editMatchPatterns"
              v-if="!isEditingPatterns">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveMatchPatterns">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditPatterns">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingPatterns" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadPatternsFailed" class="error-state">
          <el-alert
            title="加载执行结果匹配模式失败"
            type="error"
            description="请添加规则"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingPatterns" class="patterns-list">
            <div v-for="(pattern, index) in matchPatterns" :key="index" class="pattern-item">
              {{ pattern }}
            </div>
            <div v-if="matchPatterns.length === 0" class="no-pattern">
              没有配置执行结果匹配模式，点击"修改"添加匹配模式
            </div>
          </div>
          <div v-else class="patterns-edit">
            <el-input
              type="textarea"
              v-model="matchPatternsText"
              :rows="8"
              placeholder="请输入执行结果匹配模式，每行一个"
            ></el-input>
            <div class="hint">
              <h4>命令执行结果匹配模式示例：</h4>
              <p>rce_test_cmd</p>
              <p>uid=\d+\(.+\)</p>
              <p>\d+\s+\w+\s+\d+\s+\d+\s+\w+</p>
              <h4>代码执行结果匹配模式示例：</h4>
              <p>rce_test_code</p>
              <p>code_exec_test</p>
              <p>49</p>
            </div>
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
  name: 'RceRules',
  data() {
    return {
      // RCE载荷
      isEditingPayloads: false,
      isLoadingPayloads: false,
      loadPayloadsFailed: false,
      payloads: [],
      payloadsText: '',
      payloadRuleId: null,  // 用于存储规则ID，便于更新

      // 匹配模式
      isEditingPatterns: false,
      isLoadingPatterns: false,
      loadPatternsFailed: false,
      matchPatterns: [],
      matchPatternsText: '',
      patternsRuleId: null  // 用于存储规则ID，便于更新
    };
  },
  created() {
    this.fetchRceRules();
  },
  methods: {
    async fetchRceRules() {
      // 获取所有RCE相关规则
      this.fetchPayloads();
      this.fetchMatchPatterns();
    },

    async fetchPayloads() {
      this.isLoadingPayloads = true;
      this.loadPayloadsFailed = false;

      try {
        // 获取RCE载荷规则
        const rules = await this.fetchVulnScanRulesByType('command_injection', 'payload');

        if (rules.length > 0) {
          // 找到RCE载荷规则
          const rule = rules[0];  // 使用第一条规则
          this.payloadRuleId = rule.id;

          // 解析载荷
          this.payloads = this.parseRuleContent(rule.rule_content);
          this.payloadsText = this.payloads.join('\n');

          console.log("找到RCE载荷规则:", rule);
        } else {
          console.log("未找到RCE载荷规则");
          // 初始化为空
          this.payloads = [];
          this.payloadsText = '';
          this.payloadRuleId = null;
        }
      } catch (error) {
        console.error('获取RCE载荷规则失败', error);
        this.loadPayloadsFailed = true;

        // 初始化为空
        this.payloads = [];
        this.payloadsText = '';

        ElMessage.error('获取RCE载荷规则失败，请手动添加规则');
      } finally {
        this.isLoadingPayloads = false;
      }
    },

    async fetchMatchPatterns() {
      this.isLoadingPatterns = true;
      this.loadPatternsFailed = false;

      try {
        // 获取匹配模式规则
        const rules = await this.fetchVulnScanRulesByType('command_injection', 'match_pattern');

        if (rules.length > 0) {
          // 找到匹配模式规则
          const rule = rules[0];  // 使用第一条规则
          this.patternsRuleId = rule.id;

          // 解析匹配模式
          this.matchPatterns = this.parseRuleContent(rule.rule_content);
          this.matchPatternsText = this.matchPatterns.join('\n');

          console.log("找到RCE匹配模式规则:", rule);
        } else {
          console.log("未找到RCE匹配模式规则");
          // 初始化为空
          this.matchPatterns = [];
          this.matchPatternsText = '';
          this.patternsRuleId = null;
        }
      } catch (error) {
        console.error('获取RCE匹配模式规则失败', error);
        this.loadPatternsFailed = true;

        // 初始化为空
        this.matchPatterns = [];
        this.matchPatternsText = '';

        ElMessage.error('获取RCE匹配模式规则失败，请手动添加规则');
      } finally {
        this.isLoadingPatterns = false;
      }
    },

    // 辅助方法：根据类型获取漏洞扫描规则
    async fetchVulnScanRulesByType(vulnType, subType) {
      try {
        // 获取指定类型的漏洞扫描规则
        const response = await rulesAPI.getVulnScanRulesByType(vulnType);

        // 从结果中筛选出子类型匹配的规则
        let rules = [];
        if (Array.isArray(response)) {
          rules = response;
        } else if (response && Array.isArray(response.results)) {
          rules = response.results;
        }

        // 过滤子类型
        return rules.filter(rule => {
          try {
            const ruleData = JSON.parse(rule.rule_content);
            return ruleData.subType === subType;
          } catch (e) {
            // 如果解析失败，检查rule_content中是否包含子类型标识
            return rule.rule_content.includes(`"subType":"${subType}"`) ||
                  rule.rule_content.includes(`"subType": "${subType}"`);
          }
        });
      } catch (error) {
        console.error(`获取${vulnType}/${subType}类型规则失败`, error);
        return [];
      }
    },

    // 解析规则内容
    parseRuleContent(ruleContent) {
      try {
        const data = JSON.parse(ruleContent);
        return Array.isArray(data.payloads) ? data.payloads : [];
      } catch (e) {
        console.error('解析规则内容失败', e);
        return [];
      }
    },

    // 编辑方法
    editPayloads() {
      this.isEditingPayloads = true;
    },

    cancelEditPayloads() {
      this.isEditingPayloads = false;
      this.payloadsText = this.payloads.join('\n');
    },

    editMatchPatterns() {
      this.isEditingPatterns = true;
    },

    cancelEditPatterns() {
      this.isEditingPatterns = false;
      this.matchPatternsText = this.matchPatterns.join('\n');
    },

    // 保存方法
    async savePayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.payloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'command_injection',
          name: '命令/代码执行规则',
          description: '用于检测命令执行和代码执行漏洞的测试载荷',
          rule_content: JSON.stringify({
            subType: 'payload',
            payloads: payloads
          })
        };

        console.log("准备保存RCE载荷规则:", ruleData);

        if (this.payloadRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.payloadRuleId, ruleData);
          ElMessage.success('命令/代码执行规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.payloadRuleId = response.id;
          ElMessage.success('命令/代码执行规则创建成功');
        }

        // 更新显示
        this.payloads = payloads;
        this.isEditingPayloads = false;
      } catch (error) {
        console.error('保存RCE载荷规则失败', error);
        ElMessage.error('保存命令/代码执行规则失败');
      }
    },

    async saveMatchPatterns() {
      try {
        // 处理文本框中的内容，分割为匹配模式数组
        const patterns = this.matchPatternsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'command_injection',
          name: '执行结果匹配模式',
          description: '用于检测命令/代码执行成功的匹配模式',
          rule_content: JSON.stringify({
            subType: 'match_pattern',
            payloads: patterns
          })
        };

        console.log("准备保存执行结果匹配模式:", ruleData);

        if (this.patternsRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.patternsRuleId, ruleData);
          ElMessage.success('执行结果匹配模式更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.patternsRuleId = response.id;
          ElMessage.success('执行结果匹配模式创建成功');
        }

        // 更新显示
        this.matchPatterns = patterns;
        this.isEditingPatterns = false;
      } catch (error) {
        console.error('保存执行结果匹配模式失败', error);
        ElMessage.error('保存执行结果匹配模式失败');
      }
    }
  }
};
</script>

<style scoped>
.rce-rules {
  margin-bottom: 30px;
}

.rce-rules h3 {
  margin-bottom: 15px;
  font-size: 18px;
  color: #303133;
  padding-left: 10px;
  border-left: 4px solid #409EFF;
}

.rules-container {
  background-color: #f5f7fa;
  border-radius: 4px;
  padding: 16px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}

.rule-section {
  margin-bottom: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid #e6e6e6;
}

.rule-section:last-child {
  margin-bottom: 0;
  padding-bottom: 0;
  border-bottom: none;
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
  color: #303133;
}

.rule-desc {
  font-size: 12px;
  color: #909399;
}

.rules-content {
  min-height: 100px;
}

.payloads-list, .patterns-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  min-height: 50px;
}

.payload-item, .pattern-item {
  background-color: #ecf5ff;
  color: #409eff;
  padding: 5px 10px;
  border-radius: 4px;
  font-family: monospace;
}

.no-payload, .no-pattern {
  color: #909399;
  font-style: italic;
}

.payloads-edit, .patterns-edit {
  margin-top: 10px;
}

.hint {
  margin-top: 10px;
  padding: 12px;
  background-color: #f8f8f8;
  border-radius: 4px;
  border-left: 3px solid #409EFF;
}

.hint h4 {
  margin-top: 0;
  margin-bottom: 5px;
  font-size: 14px;
  color: #409EFF;
}

.hint p {
  margin: 5px 0;
  font-size: 12px;
  color: #606266;
  font-family: monospace;
}

.loading-state {
  padding: 20px 0;
}

.error-state {
  margin: 20px 0;
}
</style>