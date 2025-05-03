<!-- frontend/scan_system_frontend/src/components/rules/RceRules.vue -->
<template>
  <div class="rce-rules">
    <h3>RCE命令执行设置</h3>
    <div class="rules-container">
      <!-- 系统命令执行载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">系统命令执行载荷</span>
            <span class="rule-desc">添加用于检测系统命令执行的测试载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editOsCommandPayloads"
              v-if="!isEditingOsCommand">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveOsCommandPayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditOsCommand">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingOsCommand" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadOsCommandFailed" class="error-state">
          <el-alert
            title="加载系统命令执行规则失败"
            type="error"
            description="请添加规则"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingOsCommand" class="payloads-list">
            <div v-for="(payload, index) in osCommandPayloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="osCommandPayloads.length === 0" class="no-payload">
              没有配置系统命令执行载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="osCommandPayloadsText"
              :rows="8"
              placeholder="请输入系统命令执行载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: |echo cmd_inj_test, ;cat /etc/passwd, `id`, $(whoami)
            </div>
          </div>
        </div>
      </div>

      <!-- 代码执行载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">代码执行载荷</span>
            <span class="rule-desc">添加用于检测PHP、Java、Python等代码执行的测试载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editCodePayloads"
              v-if="!isEditingCode">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveCodePayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditCode">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingCode" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadCodeFailed" class="error-state">
          <el-alert
            title="加载代码执行规则失败"
            type="error"
            description="请添加规则"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingCode" class="payloads-list">
            <div v-for="(payload, index) in codePayloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="codePayloads.length === 0" class="no-payload">
              没有配置代码执行载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="codePayloadsText"
              :rows="8"
              placeholder="请输入代码执行载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: ${system('whoami')}, &lt;?php echo('code_inj_test'); ?&gt;, eval("print('code_inj_test')")
            </div>
          </div>
        </div>
      </div>

      <!-- RCE匹配规则 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">RCE匹配模式</span>
            <span class="rule-desc">配置用于检测RCE漏洞成功的匹配模式</span>
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
            title="加载RCE匹配模式失败"
            type="error"
            description="请添加规则"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingPatterns" class="patterns-display">
            <el-descriptions :column="1" border v-if="Object.keys(matchPatterns).length > 0">
              <el-descriptions-item v-for="(patterns, type) in matchPatterns" :key="type" :label="getMatchTypeLabel(type)">
                <div class="pattern-list">
                  <div v-for="(pattern, index) in patterns" :key="index" class="pattern-item">
                    {{ pattern }}
                  </div>
                </div>
              </el-descriptions-item>
            </el-descriptions>
            <div v-if="Object.keys(matchPatterns).length === 0" class="no-patterns">
              没有配置RCE匹配模式，点击"修改"添加匹配模式
            </div>
          </div>
          <div v-else class="patterns-edit">
            <p class="context-edit-hint">请以JSON格式编辑RCE匹配模式：</p>
            <el-input
              type="textarea"
              v-model="matchPatternsText"
              :rows="10"
              placeholder="请输入RCE匹配模式 (JSON格式)"
            ></el-input>
            <div class="hint">
              样例: {"os_command": ["cmd_inj_test", "uid=", "gid=", "groups="],
                    "code_injection": ["code_inj_test", "PHP Version", "eval()"]}
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
      // 系统命令执行载荷
      isEditingOsCommand: false,
      isLoadingOsCommand: false,
      loadOsCommandFailed: false,
      osCommandPayloads: [],
      osCommandPayloadsText: '',
      osCommandRuleId: null,  // 用于存储规则ID，便于更新

      // 代码执行载荷
      isEditingCode: false,
      isLoadingCode: false,
      loadCodeFailed: false,
      codePayloads: [],
      codePayloadsText: '',
      codeRuleId: null,  // 用于存储规则ID，便于更新

      // RCE匹配模式
      isEditingPatterns: false,
      isLoadingPatterns: false,
      loadPatternsFailed: false,
      matchPatterns: {},
      matchPatternsText: '',
      patternsRuleId: null  // 用于存储规则ID，便于更新
    };
  },
  created() {
    this.fetchRceRules();
  },
  methods: {
    async fetchRceRules() {
      // 获取所有RCE规则
      this.fetchOsCommandPayloads();
      this.fetchCodePayloads();
      this.fetchMatchPatterns();
    },

    async fetchOsCommandPayloads() {
      this.isLoadingOsCommand = true;
      this.loadOsCommandFailed = false;

      try {
        // 获取系统命令执行载荷规则
        const rules = await this.fetchVulnScanRulesByType('command_injection', 'os_command');

        if (rules.length > 0) {
          // 找到系统命令执行规则
          const rule = rules[0];  // 使用第一条规则
          this.osCommandRuleId = rule.id;

          // 解析载荷
          this.osCommandPayloads = this.parseRuleContent(rule.rule_content);
          this.osCommandPayloadsText = this.osCommandPayloads.join('\n');

          console.log("找到系统命令执行规则:", rule);
        } else {
          console.log("未找到系统命令执行规则");
          // 不设置默认值，保持为空数组
          this.osCommandPayloads = [];
          this.osCommandPayloadsText = '';
          this.osCommandRuleId = null;
        }
      } catch (error) {
        console.error('获取系统命令执行规则失败', error);
        this.loadOsCommandFailed = true;

        // 不设置默认值，保持为空数组
        this.osCommandPayloads = [];
        this.osCommandPayloadsText = '';

        ElMessage.error('获取系统命令执行规则失败，请添加规则');
      } finally {
        this.isLoadingOsCommand = false;
      }
    },

    async fetchCodePayloads() {
      this.isLoadingCode = true;
      this.loadCodeFailed = false;

      try {
        // 获取代码执行载荷规则
        const rules = await this.fetchVulnScanRulesByType('command_injection', 'code_injection');

        if (rules.length > 0) {
          // 找到代码执行规则
          const rule = rules[0];  // 使用第一条规则
          this.codeRuleId = rule.id;

          // 解析载荷
          this.codePayloads = this.parseRuleContent(rule.rule_content);
          this.codePayloadsText = this.codePayloads.join('\n');

          console.log("找到代码执行规则:", rule);
        } else {
          console.log("未找到代码执行规则");
          // 不设置默认值，保持为空数组
          this.codePayloads = [];
          this.codePayloadsText = '';
          this.codeRuleId = null;
        }
      } catch (error) {
        console.error('获取代码执行规则失败', error);
        this.loadCodeFailed = true;

        // 不设置默认值，保持为空数组
        this.codePayloads = [];
        this.codePayloadsText = '';

        ElMessage.error('获取代码执行规则失败，请添加规则');
      } finally {
        this.isLoadingCode = false;
      }
    },

    async fetchMatchPatterns() {
      this.isLoadingPatterns = true;
      this.loadPatternsFailed = false;

      try {
        // 获取RCE匹配模式规则
        const rules = await this.fetchVulnScanRulesByType('command_injection', 'match_patterns');

        if (rules.length > 0) {
          // 找到匹配模式规则
          const rule = rules[0];  // 使用第一条规则
          this.patternsRuleId = rule.id;

          // 解析匹配模式
          try {
            const ruleContent = JSON.parse(rule.rule_content);
            if (ruleContent.patterns && typeof ruleContent.patterns === 'object') {
              this.matchPatterns = ruleContent.patterns;
              this.matchPatternsText = JSON.stringify(ruleContent.patterns, null, 2);
            } else {
              throw new Error("规则内容格式不正确");
            }
          } catch (e) {
            console.error("解析RCE匹配模式失败:", e);
            throw e;
          }

          console.log("找到RCE匹配模式规则:", rule);
        } else {
          console.log("未找到RCE匹配模式规则");
          // 不设置默认值，保持为空对象
          this.matchPatterns = {};
          this.matchPatternsText = '';
          this.patternsRuleId = null;
        }
      } catch (error) {
        console.error('获取RCE匹配模式规则失败', error);
        this.loadPatternsFailed = true;

        // 不设置默认值，保持为空对象
        this.matchPatterns = {};
        this.matchPatternsText = '';

        ElMessage.error('获取RCE匹配模式规则失败，请添加规则');
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

    // 获取匹配类型标签
    getMatchTypeLabel(type) {
      const labels = {
        "os_command": "系统命令执行匹配",
        "code_injection": "代码执行匹配"
      };
      return labels[type] || type;
    },

    // 编辑方法
    editOsCommandPayloads() {
      this.isEditingOsCommand = true;
    },

    cancelEditOsCommand() {
      this.isEditingOsCommand = false;
      this.osCommandPayloadsText = this.osCommandPayloads.join('\n');
    },

    editCodePayloads() {
      this.isEditingCode = true;
    },

    cancelEditCode() {
      this.isEditingCode = false;
      this.codePayloadsText = this.codePayloads.join('\n');
    },

    editMatchPatterns() {
      this.isEditingPatterns = true;

      // 如果没有内容，提供一个空的JSON对象框架作为模板
      if (!this.matchPatternsText) {
        this.matchPatternsText = '{\n  "os_command": [],\n  "code_injection": []\n}';
      }
    },

    cancelEditPatterns() {
      this.isEditingPatterns = false;
      this.matchPatternsText = JSON.stringify(this.matchPatterns, null, 2);
    },

    // 保存方法
    async saveOsCommandPayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.osCommandPayloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'command_injection',
          name: '系统命令执行规则',
          description: '用于检测系统命令执行漏洞的测试载荷',
          rule_content: JSON.stringify({
            subType: 'os_command',
            payloads: payloads
          })
        };

        console.log("准备保存系统命令执行规则:", ruleData);

        if (this.osCommandRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.osCommandRuleId, ruleData);
          ElMessage.success('系统命令执行规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.osCommandRuleId = response.id;
          ElMessage.success('系统命令执行规则创建成功');
        }

        // 更新显示
        this.osCommandPayloads = payloads;
        this.isEditingOsCommand = false;
      } catch (error) {
        console.error('保存系统命令执行规则失败', error);
        ElMessage.error('保存系统命令执行规则失败');
      }
    },

    async saveCodePayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.codePayloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'command_injection',
          name: '代码执行规则',
          description: '用于检测PHP、Java、Python等代码执行漏洞的测试载荷',
          rule_content: JSON.stringify({
            subType: 'code_injection',
            payloads: payloads
          })
        };

        console.log("准备保存代码执行规则:", ruleData);

        if (this.codeRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.codeRuleId, ruleData);
          ElMessage.success('代码执行规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.codeRuleId = response.id;
          ElMessage.success('代码执行规则创建成功');
        }

        // 更新显示
        this.codePayloads = payloads;
        this.isEditingCode = false;
      } catch (error) {
        console.error('保存代码执行规则失败', error);
        ElMessage.error('保存代码执行规则失败');
      }
    },

    async saveMatchPatterns() {
      try {
        // 处理文本框中的内容，解析为JSON对象
        let patterns;
        try {
          patterns = JSON.parse(this.matchPatternsText);
          // 验证是否为对象
          if (typeof patterns !== 'object' || Array.isArray(patterns) || patterns === null) {
            throw new Error("必须是JSON对象格式");
          }
        } catch (e) {
          ElMessage.error('RCE匹配模式必须是有效的JSON对象格式');
          return;
        }

        // 准备规则数据
        const ruleData = {
          vuln_type: 'command_injection',
          name: 'RCE匹配模式规则',
          description: '用于检测RCE漏洞成功的匹配模式',
          rule_content: JSON.stringify({
            subType: 'match_patterns',
            patterns: patterns
          })
        };

        console.log("准备保存RCE匹配模式规则:", ruleData);

        if (this.patternsRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.patternsRuleId, ruleData);
          ElMessage.success('RCE匹配模式规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.patternsRuleId = response.id;
          ElMessage.success('RCE匹配模式规则创建成功');
        }

        // 更新显示
        this.matchPatterns = patterns;
        this.isEditingPatterns = false;
      } catch (error) {
        console.error('保存RCE匹配模式规则失败', error);
        ElMessage.error('保存RCE匹配模式规则失败');
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

.pattern-list {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.pattern-item {
  font-family: monospace;
  color: #606266;
}

.no-payload, .no-patterns {
  color: #909399;
  font-style: italic;
}

.payloads-edit, .patterns-edit {
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