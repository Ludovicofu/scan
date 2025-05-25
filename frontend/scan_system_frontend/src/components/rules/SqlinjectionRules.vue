<template>
  <div class="sqlinjection-rules">
    <h3>SQL注入扫描设置</h3>
    <div class="rules-container">
      <!-- 回显型SQL注入载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">回显型SQL注入载荷</span>
            <span class="rule-desc">添加能够引发明显回显的SQL注入测试载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editErrorPayloads"
              v-if="!isEditingError">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveErrorPayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditError">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingError" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadErrorFailed" class="error-state">
          <el-alert
            title="加载回显型SQL注入规则失败"
            type="error"
            description="使用默认配置"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingError" class="payloads-list">
            <div v-for="(payload, index) in errorPayloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="errorPayloads.length === 0" class="no-payload">
              没有配置回显型SQL注入载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="errorPayloadsText"
              :rows="8"
              placeholder="请输入回显型SQL注入载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: ', " UNION SELECT 1,2,3--, ' OR '1'='1
            </div>
          </div>
        </div>
      </div>

      <!-- HTTP头注入设置 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">HTTP头注入设置</span>
            <span class="rule-desc">选择要进行SQL注入测试的HTTP头</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editHttpHeaders"
              v-if="!isEditingHeaders">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveHttpHeaders">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditHeaders">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingHeaders" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadHeadersFailed" class="error-state">
          <el-alert
            title="加载HTTP头注入设置失败"
            type="error"
            description="使用默认配置"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingHeaders" class="headers-list">
            <div v-for="(header, index) in httpHeaders" :key="index" class="header-item">
              {{ header }}
            </div>
            <div v-if="httpHeaders.length === 0" class="no-header">
              没有配置HTTP头注入测试，点击"修改"添加HTTP头
            </div>
          </div>
          <div v-else class="headers-edit">
            <el-input
              type="textarea"
              v-model="httpHeadersText"
              :rows="5"
              placeholder="请输入要测试的HTTP头，每行一个"
            ></el-input>
            <div class="hint">
              样例: Cookie, X-Forwarded-For, User-Agent, Referer
            </div>
          </div>
        </div>
      </div>

      <!-- SQL错误匹配模式 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">SQL错误匹配模式</span>
            <span class="rule-desc">添加用于检测SQL注入的错误信息匹配模式</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editErrorPatterns"
              v-if="!isEditingPattern">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveErrorPatterns">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditPattern">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingPattern" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadPatternFailed" class="error-state">
          <el-alert
            title="加载SQL错误匹配模式失败"
            type="error"
            description="使用默认配置"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingPattern" class="patterns-list">
            <div v-for="(pattern, index) in errorPatterns" :key="index" class="pattern-item">
              {{ pattern }}
            </div>
            <div v-if="errorPatterns.length === 0" class="no-pattern">
              没有配置SQL错误匹配模式，点击"修改"添加匹配模式
            </div>
          </div>
          <div v-else class="patterns-edit">
            <el-input
              type="textarea"
              v-model="errorPatternsText"
              :rows="8"
              placeholder="请输入SQL错误匹配模式，每行一个"
            ></el-input>
            <div class="hint">
              样例: SQL syntax.*MySQL, Warning.*mysqli, ORA-[0-9][0-9][0-9][0-9], SQLSTATE
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
  name: 'SqlinjectionRules',
  data() {
    return {
      // 回显型SQL注入载荷
      isEditingError: false,
      isLoadingError: false,
      loadErrorFailed: false,
      errorPayloads: [],
      errorPayloadsText: '',
      errorRuleId: null,  // 用于存储规则ID，便于更新

      // HTTP头注入设置
      isEditingHeaders: false,
      isLoadingHeaders: false,
      loadHeadersFailed: false,
      httpHeaders: [],
      httpHeadersText: '',
      headersRuleId: null,  // 用于存储规则ID，便于更新

      // SQL错误匹配模式
      isEditingPattern: false,
      isLoadingPattern: false,
      loadPatternFailed: false,
      errorPatterns: [],
      errorPatternsText: '',
      patternRuleId: null  // 用于存储规则ID，便于更新
    };
  },
  created() {
    this.fetchSqlinjectionRules();
  },
  methods: {
    async fetchSqlinjectionRules() {
      // 获取所有SQL注入规则
      this.fetchErrorBasedRules();
      this.fetchHttpHeaderRules();
      this.fetchErrorPatternRules();
    },

    async fetchErrorBasedRules() {
      this.isLoadingError = true;
      this.loadErrorFailed = false;

      try {
        // 获取回显型SQL注入规则
        const rules = await this.fetchVulnScanRulesByType('sql_injection', 'error_based');

        if (rules.length > 0) {
          // 找到回显型规则
          const rule = rules[0];  // 使用第一条规则
          this.errorRuleId = rule.id;

          // 解析载荷
          this.errorPayloads = this.parseRuleContent(rule.rule_content);
          this.errorPayloadsText = this.errorPayloads.join('\n');

          console.log("找到回显型SQL注入规则:", rule);
        } else {
          console.log("未找到回显型SQL注入规则，使用默认值");
          // 如果没有找到规则，使用默认值
          this.errorPayloads = [
            "'",
            "\"",
            "')",
            "\";",
            "' UNION SELECT 1,2,3--",
            "\" UNION SELECT @@version,2,3--",
            "' OR '1'='1"
          ];
          this.errorPayloadsText = this.errorPayloads.join('\n');
          this.errorRuleId = null;

          // 尝试创建默认规则
          await this.createDefaultErrorBasedRule();
        }
      } catch (error) {
        console.error('获取回显型SQL注入规则失败', error);
        this.loadErrorFailed = true;

        // 使用默认值
        this.errorPayloads = [
          "'",
          "\"",
          "')",
          "\";",
          "' UNION SELECT 1,2,3--",
          "\" UNION SELECT @@version,2,3--",
          "' OR '1'='1"
        ];
        this.errorPayloadsText = this.errorPayloads.join('\n');

        ElMessage.error('获取回显型SQL注入规则失败，使用默认配置');
      } finally {
        this.isLoadingError = false;
      }
    },

    async fetchHttpHeaderRules() {
      this.isLoadingHeaders = true;
      this.loadHeadersFailed = false;

      try {
        // 获取HTTP头注入规则
        const rules = await this.fetchVulnScanRulesByType('sql_injection', 'http_header');

        if (rules.length > 0) {
          // 找到HTTP头规则
          const rule = rules[0];  // 使用第一条规则
          this.headersRuleId = rule.id;

          // 解析HTTP头
          this.httpHeaders = this.parseRuleContent(rule.rule_content);
          this.httpHeadersText = this.httpHeaders.join('\n');

          console.log("找到HTTP头注入规则:", rule);
        } else {
          console.log("未找到HTTP头注入规则，使用默认值");
          // 如果没有找到规则，使用默认值
          this.httpHeaders = [
            "Cookie",
            "X-Forwarded-For",
            "Referer",
            "User-Agent",
            "Authorization"
          ];
          this.httpHeadersText = this.httpHeaders.join('\n');
          this.headersRuleId = null;

          // 尝试创建默认规则
          await this.createDefaultHttpHeaderRule();
        }
      } catch (error) {
        console.error('获取HTTP头注入规则失败', error);
        this.loadHeadersFailed = true;

        // 使用默认值
        this.httpHeaders = [
          "Cookie",
          "X-Forwarded-For",
          "Referer",
          "User-Agent",
          "Authorization"
        ];
        this.httpHeadersText = this.httpHeaders.join('\n');

        ElMessage.error('获取HTTP头注入规则失败，使用默认配置');
      } finally {
        this.isLoadingHeaders = false;
      }
    },

    async fetchErrorPatternRules() {
      this.isLoadingPattern = true;
      this.loadPatternFailed = false;

      try {
        // 获取SQL错误匹配模式规则
        const rules = await this.fetchVulnScanRulesByType('sql_injection', 'error_pattern');

        if (rules.length > 0) {
          // 找到错误匹配模式规则
          const rule = rules[0];  // 使用第一条规则
          this.patternRuleId = rule.id;

          // 解析匹配模式
          this.errorPatterns = this.parseRuleContent(rule.rule_content);
          this.errorPatternsText = this.errorPatterns.join('\n');

          console.log("找到SQL错误匹配模式规则:", rule);
        } else {
          console.log("未找到SQL错误匹配模式规则，使用默认值");
          // 如果没有找到规则，使用默认值
          this.errorPatterns = [
            "SQL syntax.*MySQL",
            "Warning.*mysqli",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "check the manual that (corresponds to|fits) your MySQL server version",
            "MySqlClient\\.",
            "com\\.mysql\\.jdbc\\.exceptions",
            "ORA-[0-9][0-9][0-9][0-9]",
            "Oracle error",
            "Oracle.*Driver",
            "SQLSTATE\\[",
            "SQL Server message",
            "Warning.*mssql_",
            "Driver.*? SQL[\\-\\_\\ ]*Server",
            "JET Database Engine",
            "Microsoft Access Driver",
            "Syntax error \\(missing operator\\) in query expression"
          ];
          this.errorPatternsText = this.errorPatterns.join('\n');
          this.patternRuleId = null;

          // 尝试创建默认规则
          await this.createDefaultErrorPatternRule();
        }
      } catch (error) {
        console.error('获取SQL错误匹配模式规则失败', error);
        this.loadPatternFailed = true;

        // 使用默认值
        this.errorPatterns = [
          "SQL syntax.*MySQL",
          "Warning.*mysqli",
          "MySQLSyntaxErrorException",
          "valid MySQL result",
          "check the manual that (corresponds to|fits) your MySQL server version",
          "MySqlClient\\.",
          "com\\.mysql\\.jdbc\\.exceptions",
          "ORA-[0-9][0-9][0-9][0-9]",
          "Oracle error",
          "Oracle.*Driver",
          "SQLSTATE\\[",
          "SQL Server message",
          "Warning.*mssql_",
          "Driver.*? SQL[\\-\\_\\ ]*Server",
          "JET Database Engine",
          "Microsoft Access Driver",
          "Syntax error \\(missing operator\\) in query expression"
        ];
        this.errorPatternsText = this.errorPatterns.join('\n');

        ElMessage.error('获取SQL错误匹配模式规则失败，使用默认配置');
      } finally {
        this.isLoadingPattern = false;
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
    editErrorPayloads() {
      this.isEditingError = true;
    },

    cancelEditError() {
      this.isEditingError = false;
      this.errorPayloadsText = this.errorPayloads.join('\n');
    },

    editHttpHeaders() {
      this.isEditingHeaders = true;
    },

    cancelEditHeaders() {
      this.isEditingHeaders = false;
      this.httpHeadersText = this.httpHeaders.join('\n');
    },

    editErrorPatterns() {
      this.isEditingPattern = true;
    },

    cancelEditPattern() {
      this.isEditingPattern = false;
      this.errorPatternsText = this.errorPatterns.join('\n');
    },

    // 创建默认规则方法
    async createDefaultErrorBasedRule() {
      try {
        // 准备规则数据
        const ruleData = {
          vuln_type: 'sql_injection',
          name: '回显型SQL注入规则',
          description: '用于检测回显型SQL注入漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'error_based',
            payloads: this.errorPayloads
          })
        };

        console.log("创建默认回显型SQL注入规则:", ruleData);

        // 创建规则
        const response = await rulesAPI.createVulnScanRule(ruleData);
        console.log("默认回显型SQL注入规则创建成功:", response);
        this.errorRuleId = response.id;

        return response;
      } catch (error) {
        console.error('创建默认回显型SQL注入规则失败', error);
        return null;
      }
    },

    async createDefaultHttpHeaderRule() {
      try {
        // 准备规则数据
        const ruleData = {
          vuln_type: 'sql_injection',
          name: 'HTTP头SQL注入规则',
          description: '用于检测HTTP头中SQL注入漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'http_header',
            payloads: this.httpHeaders
          })
        };

        console.log("创建默认HTTP头SQL注入规则:", ruleData);

        // 创建规则
        const response = await rulesAPI.createVulnScanRule(ruleData);
        console.log("默认HTTP头SQL注入规则创建成功:", response);
        this.headersRuleId = response.id;

        return response;
      } catch (error) {
        console.error('创建默认HTTP头SQL注入规则失败', error);
        return null;
      }
    },

    async createDefaultErrorPatternRule() {
      try {
        // 准备规则数据
        const ruleData = {
          vuln_type: 'sql_injection',
          name: 'SQL错误匹配模式规则',
          description: '用于检测响应中的SQL错误信息模式',
          rule_content: JSON.stringify({
            subType: 'error_pattern',
            payloads: this.errorPatterns
          })
        };

        console.log("创建默认SQL错误匹配模式规则:", ruleData);

        // 创建规则
        const response = await rulesAPI.createVulnScanRule(ruleData);
        console.log("默认SQL错误匹配模式规则创建成功:", response);
        this.patternRuleId = response.id;

        return response;
      } catch (error) {
        console.error('创建默认SQL错误匹配模式规则失败', error);
        return null;
      }
    },

    // 保存方法
    async saveErrorPayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.errorPayloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'sql_injection',
          name: '回显型SQL注入规则',
          description: '用于检测回显型SQL注入漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'error_based',
            payloads: payloads
          })
        };

        console.log("准备保存回显型SQL注入规则:", ruleData);

        if (this.errorRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.errorRuleId, ruleData);
          ElMessage.success('回显型SQL注入规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.errorRuleId = response.id;
          ElMessage.success('回显型SQL注入规则创建成功');
        }

        // 更新显示
        this.errorPayloads = payloads;
        this.isEditingError = false;
      } catch (error) {
        console.error('保存回显型SQL注入规则失败', error);
        ElMessage.error('保存回显型SQL注入规则失败');
      }
    },

    async saveHttpHeaders() {
      try {
        // 处理文本框中的内容，分割为HTTP头数组
        const headers = this.httpHeadersText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'sql_injection',
          name: 'HTTP头SQL注入规则',
          description: '用于检测HTTP头中SQL注入漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'http_header',
            payloads: headers
          })
        };

        console.log("准备保存HTTP头SQL注入规则:", ruleData);

        if (this.headersRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.headersRuleId, ruleData);
          ElMessage.success('HTTP头SQL注入规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.headersRuleId = response.id;
          ElMessage.success('HTTP头SQL注入规则创建成功');
        }

        // 更新显示
        this.httpHeaders = headers;
        this.isEditingHeaders = false;
      } catch (error) {
        console.error('保存HTTP头SQL注入规则失败', error);
        ElMessage.error('保存HTTP头SQL注入规则失败');
      }
    },

    async saveErrorPatterns() {
      try {
        // 处理文本框中的内容，分割为匹配模式数组
        const patterns = this.errorPatternsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'sql_injection',
          name: 'SQL错误匹配模式规则',
          description: '用于检测响应中的SQL错误信息模式',
          rule_content: JSON.stringify({
            subType: 'error_pattern',
            payloads: patterns
          })
        };

        console.log("准备保存SQL错误匹配模式规则:", ruleData);

        if (this.patternRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.patternRuleId, ruleData);
          ElMessage.success('SQL错误匹配模式规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.patternRuleId = response.id;
          ElMessage.success('SQL错误匹配模式规则创建成功');
        }

        // 更新显示
        this.errorPatterns = patterns;
        this.isEditingPattern = false;
      } catch (error) {
        console.error('保存SQL错误匹配模式规则失败', error);
        ElMessage.error('保存SQL错误匹配模式规则失败');
      }
    }
  }
};
</script>

<style scoped>
.sqlinjection-rules {
  margin-bottom: 30px;
}

.sqlinjection-rules h3 {
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

.payloads-list, .headers-list, .patterns-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  min-height: 50px;
}

.payload-item, .header-item, .pattern-item {
  background-color: #ecf5ff;
  color: #409eff;
  padding: 5px 10px;
  border-radius: 4px;
  font-family: monospace;
}

.no-payload, .no-header, .no-pattern {
  color: #909399;
  font-style: italic;
}

.payloads-edit, .headers-edit, .patterns-edit {
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