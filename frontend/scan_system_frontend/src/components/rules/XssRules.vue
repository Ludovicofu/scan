<!-- frontend/scan_system_frontend/src/components/rules/XssRules.vue -->
<template>
  <div class="xss-rules">
    <h3>XSS跨站脚本扫描设置</h3>
    <div class="rules-container">
      <!-- XSS载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">XSS载荷</span>
            <span class="rule-desc">添加用于检测XSS漏洞的测试载荷</span>
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
            title="加载XSS规则失败"
            type="error"
            description="无法获取规则配置"
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
              没有配置XSS载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="payloadsText"
              :rows="8"
              placeholder="请输入XSS载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: &lt;script&gt;alert(1)&lt;/script&gt;, &lt;img src=x onerror=alert(1)&gt;
            </div>
          </div>
        </div>
      </div>

      <!-- XSS上下文匹配模式 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">XSS上下文匹配模式</span>
            <span class="rule-desc">配置用于检测XSS漏洞的不同上下文的匹配模式</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editContextPatterns"
              v-if="!isEditingContext">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveContextPatterns">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditContext">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingContext" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadContextFailed" class="error-state">
          <el-alert
            title="加载XSS上下文匹配模式失败"
            type="error"
            description="无法获取规则配置"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingContext" class="context-list">
            <el-descriptions :column="1" border>
              <el-descriptions-item v-for="(pattern, context) in contextPatterns" :key="context" :label="getContextLabel(context)">
                <code>{{ pattern }}</code>
              </el-descriptions-item>
            </el-descriptions>
            <div v-if="Object.keys(contextPatterns).length === 0" class="no-context">
              没有配置XSS上下文匹配模式，点击"修改"添加匹配模式
            </div>
          </div>
          <div v-else class="context-edit">
            <p class="context-edit-hint">请以JSON格式编辑上下文匹配模式：</p>
            <el-input
              type="textarea"
              v-model="contextPatternsText"
              :rows="10"
              placeholder="请输入XSS上下文匹配模式 (JSON格式)"
            ></el-input>
            <div class="hint">
              样例: {"html": "&lt;[^&gt;]*&gt;(.*?)&lt;/[^&gt;]*&gt;", "attribute": "&lt;[^&gt;]*[a-zA-Z0-9]+=([\'\"])(.*?)\\1[^&gt;]*&gt;"}
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
  name: 'XssRules',
  data() {
    return {
      // XSS载荷
      isEditingPayloads: false,
      isLoadingPayloads: false,
      loadPayloadsFailed: false,
      payloads: [],
      payloadsText: '',
      payloadRuleId: null,  // 用于存储规则ID，便于更新

      // XSS上下文匹配模式
      isEditingContext: false,
      isLoadingContext: false,
      loadContextFailed: false,
      contextPatterns: {},
      contextPatternsText: '',
      contextRuleId: null  // 用于存储规则ID，便于更新
    };
  },
  created() {
    this.fetchXssRules();
  },
  methods: {
    async fetchXssRules() {
      // 获取XSS规则
      this.fetchXssPayloads();
      this.fetchContextPatternRules();
    },

    async fetchXssPayloads() {
      this.isLoadingPayloads = true;
      this.loadPayloadsFailed = false;

      try {
        // 获取XSS载荷规则
        const rules = await this.fetchVulnScanRulesByType('xss', 'payload');

        if (rules.length > 0) {
          // 找到XSS载荷规则
          const rule = rules[0];  // 使用第一条规则
          this.payloadRuleId = rule.id;

          // 解析载荷
          this.payloads = this.parseRuleContent(rule.rule_content);
          this.payloadsText = this.payloads.join('\n');

          console.log("找到XSS载荷规则:", rule);
        } else {
          console.log("未找到XSS载荷规则，不进行扫描");
          // 不设置默认值，保持数组为空
          this.payloads = [];
          this.payloadsText = '';
          this.payloadRuleId = null;
        }
      } catch (error) {
        console.error('获取XSS载荷规则失败', error);
        this.loadPayloadsFailed = true;
        // 出错时不设置默认值
        this.payloads = [];
        this.payloadsText = '';

        ElMessage.error('获取XSS载荷规则失败');
      } finally {
        this.isLoadingPayloads = false;
      }
    },

    async fetchContextPatternRules() {
      this.isLoadingContext = true;
      this.loadContextFailed = false;

      try {
        // 获取上下文匹配模式规则
        const rules = await this.fetchVulnScanRulesByType('xss', 'context_pattern');

        if (rules.length > 0) {
          // 找到上下文匹配模式规则
          const rule = rules[0];  // 使用第一条规则
          this.contextRuleId = rule.id;

          // 解析上下文匹配模式
          try {
            const ruleContent = JSON.parse(rule.rule_content);
            if (ruleContent.patterns && typeof ruleContent.patterns === 'object') {
              this.contextPatterns = ruleContent.patterns;
              this.contextPatternsText = JSON.stringify(ruleContent.patterns, null, 2);
            } else {
              throw new Error("规则内容格式不正确");
            }
          } catch (e) {
            console.error("解析上下文匹配模式失败:", e);
            throw e;
          }

          console.log("找到XSS上下文匹配模式规则:", rule);
        } else {
          console.log("未找到XSS上下文匹配模式规则，不进行扫描");
          // 不设置默认值，保持对象为空
          this.contextPatterns = {};
          this.contextPatternsText = '';
          this.contextRuleId = null;
        }
      } catch (error) {
        console.error('获取XSS上下文匹配模式规则失败', error);
        this.loadContextFailed = true;
        // 出错时不设置默认值
        this.contextPatterns = {};
        this.contextPatternsText = '';

        ElMessage.error('获取XSS上下文匹配模式规则失败');
      } finally {
        this.isLoadingContext = false;
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

    editContextPatterns() {
      this.isEditingContext = true;
    },

    cancelEditContext() {
      this.isEditingContext = false;
      this.contextPatternsText = JSON.stringify(this.contextPatterns, null, 2);
    },

    getContextLabel(context) {
      const contextLabels = {
        "html": "HTML标签上下文",
        "attribute": "HTML属性上下文",
        "javascript": "JavaScript上下文",
        "url": "URL上下文",
        "css": "CSS上下文"
      };
      return contextLabels[context] || context;
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
          vuln_type: 'xss',
          name: 'XSS载荷规则',
          description: '用于检测XSS漏洞的测试载荷',
          rule_content: JSON.stringify({
            subType: 'payload',
            payloads: payloads
          })
        };

        console.log("准备保存XSS载荷规则:", ruleData);

        if (this.payloadRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.payloadRuleId, ruleData);
          ElMessage.success('XSS载荷规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.payloadRuleId = response.id;
          ElMessage.success('XSS载荷规则创建成功');
        }

        // 更新显示
        this.payloads = payloads;
        this.isEditingPayloads = false;
      } catch (error) {
        console.error('保存XSS载荷规则失败', error);
        ElMessage.error('保存XSS载荷规则失败');
      }
    },

    async saveContextPatterns() {
      try {
        // 处理文本框中的内容，解析为JSON对象
        let patterns;
        try {
          patterns = JSON.parse(this.contextPatternsText);
          // 验证是否为对象
          if (typeof patterns !== 'object' || Array.isArray(patterns) || patterns === null) {
            throw new Error("必须是JSON对象格式");
          }
        } catch (e) {
          ElMessage.error('上下文匹配模式必须是有效的JSON对象格式');
          return;
        }

        // 准备规则数据
        const ruleData = {
          vuln_type: 'xss',
          name: 'XSS上下文匹配模式规则',
          description: '用于检测XSS漏洞的不同上下文的匹配模式',
          rule_content: JSON.stringify({
            subType: 'context_pattern',
            patterns: patterns
          })
        };

        console.log("准备保存XSS上下文匹配模式规则:", ruleData);

        if (this.contextRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.contextRuleId, ruleData);
          ElMessage.success('XSS上下文匹配模式规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.contextRuleId = response.id;
          ElMessage.success('XSS上下文匹配模式规则创建成功');
        }

        // 更新显示
        this.contextPatterns = patterns;
        this.isEditingContext = false;
      } catch (error) {
        console.error('保存XSS上下文匹配模式规则失败', error);
        ElMessage.error('保存XSS上下文匹配模式规则失败');
      }
    }
  }
};
</script>

<style scoped>
.xss-rules {
  margin-bottom: 30px;
}

.xss-rules h3 {
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

.payloads-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  min-height: 50px;
}

.payload-item {
  background-color: #ecf5ff;
  color: #409eff;
  padding: 5px 10px;
  border-radius: 4px;
  font-family: monospace;
}

.no-payload, .no-context {
  color: #909399;
  font-style: italic;
}

.payloads-edit, .context-edit {
  margin-top: 10px;
}

.context-edit-hint {
  font-size: 14px;
  margin-bottom: 10px;
  color: #606266;
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