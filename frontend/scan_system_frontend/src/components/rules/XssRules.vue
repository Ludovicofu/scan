<!-- frontend/scan_system_frontend/src/components/rules/XssRules.vue -->
<template>
  <div class="xss-rules">
    <h3>XSS跨站脚本扫描设置</h3>
    <div class="rules-container">
      <!-- 反射型XSS载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">反射型XSS载荷</span>
            <span class="rule-desc">添加用于检测反射型XSS漏洞的测试载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editReflectedPayloads"
              v-if="!isEditingReflected">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveReflectedPayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditReflected">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingReflected" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadReflectedFailed" class="error-state">
          <el-alert
            title="加载反射型XSS规则失败"
            type="error"
            description="使用默认配置"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingReflected" class="payloads-list">
            <div v-for="(payload, index) in reflectedPayloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="reflectedPayloads.length === 0" class="no-payload">
              没有配置反射型XSS载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="reflectedPayloadsText"
              :rows="8"
              placeholder="请输入反射型XSS载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: &lt;script&gt;alert(1)&lt;/script&gt;, &lt;img src=x onerror=alert(1)&gt;
            </div>
          </div>
        </div>
      </div>

      <!-- 存储型XSS载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">存储型XSS载荷</span>
            <span class="rule-desc">添加用于检测存储型XSS漏洞的测试载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editStoredPayloads"
              v-if="!isEditingStored">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveStoredPayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditStored">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingStored" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadStoredFailed" class="error-state">
          <el-alert
            title="加载存储型XSS规则失败"
            type="error"
            description="使用默认配置"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingStored" class="payloads-list">
            <div v-for="(payload, index) in storedPayloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="storedPayloads.length === 0" class="no-payload">
              没有配置存储型XSS载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="storedPayloadsText"
              :rows="8"
              placeholder="请输入存储型XSS载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: &lt;script&gt;alert('stored1')&lt;/script&gt;, &lt;img src=x onerror=alert('stored2')&gt;
            </div>
          </div>
        </div>
      </div>

      <!-- DOM型XSS载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">DOM型XSS载荷</span>
            <span class="rule-desc">添加用于检测DOM型XSS漏洞的测试载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editDomPayloads"
              v-if="!isEditingDom">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveDomPayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditDom">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingDom" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadDomFailed" class="error-state">
          <el-alert
            title="加载DOM型XSS规则失败"
            type="error"
            description="使用默认配置"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingDom" class="payloads-list">
            <div v-for="(payload, index) in domPayloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="domPayloads.length === 0" class="no-payload">
              没有配置DOM型XSS载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="domPayloadsText"
              :rows="8"
              placeholder="请输入DOM型XSS载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: javascript:alert(1), #&lt;script&gt;alert(1)&lt;/script&gt;
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
            description="使用默认配置"
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
      // 反射型XSS载荷
      isEditingReflected: false,
      isLoadingReflected: false,
      loadReflectedFailed: false,
      reflectedPayloads: [],
      reflectedPayloadsText: '',
      reflectedRuleId: null,  // 用于存储规则ID，便于更新

      // 存储型XSS载荷
      isEditingStored: false,
      isLoadingStored: false,
      loadStoredFailed: false,
      storedPayloads: [],
      storedPayloadsText: '',
      storedRuleId: null,  // 用于存储规则ID，便于更新

      // DOM型XSS载荷
      isEditingDom: false,
      isLoadingDom: false,
      loadDomFailed: false,
      domPayloads: [],
      domPayloadsText: '',
      domRuleId: null,  // 用于存储规则ID，便于更新

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
      // 获取所有XSS规则
      this.fetchReflectedXssRules();
      this.fetchStoredXssRules();
      this.fetchDomXssRules();
      this.fetchContextPatternRules();
    },

    async fetchReflectedXssRules() {
      this.isLoadingReflected = true;
      this.loadReflectedFailed = false;

      try {
        // 获取反射型XSS规则
        const rules = await this.fetchVulnScanRulesByType('xss', 'reflected');

        if (rules.length > 0) {
          // 找到反射型规则
          const rule = rules[0];  // 使用第一条规则
          this.reflectedRuleId = rule.id;

          // 解析载荷
          this.reflectedPayloads = this.parseRuleContent(rule.rule_content);
          this.reflectedPayloadsText = this.reflectedPayloads.join('\n');

          console.log("找到反射型XSS规则:", rule);
        } else {
          console.log("未找到反射型XSS规则，使用默认值");
          // 如果没有找到规则，使用默认值
          this.reflectedPayloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "';alert(1);//",
            "\"><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "\"onmouseover=\"alert(1)",
            "'-alert(1)-'"
          ];
          this.reflectedPayloadsText = this.reflectedPayloads.join('\n');
          this.reflectedRuleId = null;

          // 尝试创建默认规则
          await this.createDefaultReflectedRule();
        }
      } catch (error) {
        console.error('获取反射型XSS规则失败', error);
        this.loadReflectedFailed = true;

        // 使用默认值
        this.reflectedPayloads = [
          "<script>alert(1)</script>",
          "<img src=x onerror=alert(1)>",
          "';alert(1);//",
          "\"><script>alert(1)</script>",
          "<svg/onload=alert(1)>",
          "<iframe src=\"javascript:alert(1)\"></iframe>",
          "<body onload=alert(1)>",
          "javascript:alert(1)",
          "\"onmouseover=\"alert(1)",
          "'-alert(1)-'"
        ];
        this.reflectedPayloadsText = this.reflectedPayloads.join('\n');

        ElMessage.error('获取反射型XSS规则失败，使用默认配置');
      } finally {
        this.isLoadingReflected = false;
      }
    },

    async fetchStoredXssRules() {
      this.isLoadingStored = true;
      this.loadStoredFailed = false;

      try {
        // 获取存储型XSS规则
        const rules = await this.fetchVulnScanRulesByType('xss', 'stored');

        if (rules.length > 0) {
          // 找到存储型规则
          const rule = rules[0];  // 使用第一条规则
          this.storedRuleId = rule.id;

          // 解析载荷
          this.storedPayloads = this.parseRuleContent(rule.rule_content);
          this.storedPayloadsText = this.storedPayloads.join('\n');

          console.log("找到存储型XSS规则:", rule);
        } else {
          console.log("未找到存储型XSS规则，使用默认值");
          // 如果没有找到规则，使用默认值
          this.storedPayloads = [
            "<script>alert('stored_xss_1')</script>",
            "<img src=x onerror=alert('stored_xss_2')>",
            "<svg/onload=alert('stored_xss_3')>",
            "<iframe src=\"javascript:alert('stored_xss_4')\"></iframe>"
          ];
          this.storedPayloadsText = this.storedPayloads.join('\n');
          this.storedRuleId = null;

          // 尝试创建默认规则
          await this.createDefaultStoredRule();
        }
      } catch (error) {
        console.error('获取存储型XSS规则失败', error);
        this.loadStoredFailed = true;

        // 使用默认值
        this.storedPayloads = [
          "<script>alert('stored_xss_1')</script>",
          "<img src=x onerror=alert('stored_xss_2')>",
          "<svg/onload=alert('stored_xss_3')>",
          "<iframe src=\"javascript:alert('stored_xss_4')\"></iframe>"
        ];
        this.storedPayloadsText = this.storedPayloads.join('\n');

        ElMessage.error('获取存储型XSS规则失败，使用默认配置');
      } finally {
        this.isLoadingStored = false;
      }
    },

    async fetchDomXssRules() {
      this.isLoadingDom = true;
      this.loadDomFailed = false;

      try {
        // 获取DOM型XSS规则
        const rules = await this.fetchVulnScanRulesByType('xss', 'dom');

        if (rules.length > 0) {
          // 找到DOM型规则
          const rule = rules[0];  // 使用第一条规则
          this.domRuleId = rule.id;

          // 解析载荷
          this.domPayloads = this.parseRuleContent(rule.rule_content);
          this.domPayloadsText = this.domPayloads.join('\n');

          console.log("找到DOM型XSS规则:", rule);
        } else {
          console.log("未找到DOM型XSS规则，使用默认值");
          // 如果没有找到规则，使用默认值
          this.domPayloads = [
            "javascript:alert(1)",
            "#<script>alert(1)</script>",
            "?q=<script>alert(1)</script>",
            "?param=';alert(1);//",
            "#javascript:alert(1)"
          ];
          this.domPayloadsText = this.domPayloads.join('\n');
          this.domRuleId = null;

          // 尝试创建默认规则
          await this.createDefaultDomRule();
        }
      } catch (error) {
        console.error('获取DOM型XSS规则失败', error);
        this.loadDomFailed = true;

        // 使用默认值
        this.domPayloads = [
          "javascript:alert(1)",
          "#<script>alert(1)</script>",
          "?q=<script>alert(1)</script>",
          "?param=';alert(1);//",
          "#javascript:alert(1)"
        ];
        this.domPayloadsText = this.domPayloads.join('\n');

        ElMessage.error('获取DOM型XSS规则失败，使用默认配置');
      } finally {
        this.isLoadingDom = false;
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
          console.log("未找到XSS上下文匹配模式规则，使用默认值");
          // 如果没有找到规则，使用默认值
          this.contextPatterns = {
            "html": "<[^>]*>(.*?)</[^>]*>",
            "attribute": "<[^>]*[a-zA-Z0-9]+=([\'\"])(.*?)\\1[^>]*>",
            "javascript": "<script[^>]*>(.*?)</script>",
            "url": "(href|src|action|url)\\s*=\\s*(['\"])(.*?)\\2"
          };
          this.contextPatternsText = JSON.stringify(this.contextPatterns, null, 2);
          this.contextRuleId = null;

          // 尝试创建默认规则
          await this.createDefaultContextPatternRule();
        }
      } catch (error) {
        console.error('获取XSS上下文匹配模式规则失败', error);
        this.loadContextFailed = true;

        // 使用默认值
        this.contextPatterns = {
          "html": "<[^>]*>(.*?)</[^>]*>",
          "attribute": "<[^>]*[a-zA-Z0-9]+=([\'\"])(.*?)\\1[^>]*>",
          "javascript": "<script[^>]*>(.*?)</script>",
          "url": "(href|src|action|url)\\s*=\\s*(['\"])(.*?)\\2"
        };
        this.contextPatternsText = JSON.stringify(this.contextPatterns, null, 2);

        ElMessage.error('获取XSS上下文匹配模式规则失败，使用默认配置');
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
    editReflectedPayloads() {
      this.isEditingReflected = true;
    },

    cancelEditReflected() {
      this.isEditingReflected = false;
      this.reflectedPayloadsText = this.reflectedPayloads.join('\n');
    },

    editStoredPayloads() {
      this.isEditingStored = true;
    },

    cancelEditStored() {
      this.isEditingStored = false;
      this.storedPayloadsText = this.storedPayloads.join('\n');
    },

    editDomPayloads() {
      this.isEditingDom = true;
    },

    cancelEditDom() {
      this.isEditingDom = false;
      this.domPayloadsText = this.domPayloads.join('\n');
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

    // 创建默认规则方法
    async createDefaultReflectedRule() {
      try {
        // 准备规则数据
        const ruleData = {
          vuln_type: 'xss',
          name: '反射型XSS规则',
          description: '用于检测反射型XSS漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'reflected',
            payloads: this.reflectedPayloads
          })
        };

        console.log("创建默认反射型XSS规则:", ruleData);

        // 创建规则
        const response = await rulesAPI.createVulnScanRule(ruleData);
        console.log("默认反射型XSS规则创建成功:", response);
        this.reflectedRuleId = response.id;

        return response;
      } catch (error) {
        console.error('创建默认反射型XSS规则失败', error);
        return null;
      }
    },

    async createDefaultStoredRule() {
      try {
        // 准备规则数据
        const ruleData = {
          vuln_type: 'xss',
          name: '存储型XSS规则',
          description: '用于检测存储型XSS漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'stored',
            payloads: this.storedPayloads
          })
        };

        console.log("创建默认存储型XSS规则:", ruleData);

        // 创建规则
        const response = await rulesAPI.createVulnScanRule(ruleData);
        console.log("默认存储型XSS规则创建成功:", response);
        this.storedRuleId = response.id;

        return response;
      } catch (error) {
        console.error('创建默认存储型XSS规则失败', error);
        return null;
      }
    },

    async createDefaultDomRule() {
      try {
        // 准备规则数据
        const ruleData = {
          vuln_type: 'xss',
          name: 'DOM型XSS规则',
          description: '用于检测DOM型XSS漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'dom',
            payloads: this.domPayloads
          })
        };

        console.log("创建默认DOM型XSS规则:", ruleData);

        // 创建规则
        const response = await rulesAPI.createVulnScanRule(ruleData);
        console.log("默认DOM型XSS规则创建成功:", response);
        this.domRuleId = response.id;

        return response;
      } catch (error) {
        console.error('创建默认DOM型XSS规则失败', error);
        return null;
      }
    },

    async createDefaultContextPatternRule() {
      try {
        // 准备规则数据
        const ruleData = {
          vuln_type: 'xss',
          name: 'XSS上下文匹配模式规则',
          description: '用于检测XSS漏洞的不同上下文的匹配模式',
          rule_content: JSON.stringify({
            subType: 'context_pattern',
            patterns: this.contextPatterns
          })
        };

        console.log("创建默认XSS上下文匹配模式规则:", ruleData);

        // 创建规则
        const response = await rulesAPI.createVulnScanRule(ruleData);
        console.log("默认XSS上下文匹配模式规则创建成功:", response);
        this.contextRuleId = response.id;

        return response;
      } catch (error) {
        console.error('创建默认XSS上下文匹配模式规则失败', error);
        return null;
      }
    },

    // 保存方法
    async saveReflectedPayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.reflectedPayloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'xss',
          name: '反射型XSS规则',
          description: '用于检测反射型XSS漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'reflected',
            payloads: payloads
          })
        };

        console.log("准备保存反射型XSS规则:", ruleData);

        if (this.reflectedRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.reflectedRuleId, ruleData);
          ElMessage.success('反射型XSS规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.reflectedRuleId = response.id;
          ElMessage.success('反射型XSS规则创建成功');
        }

        // 更新显示
        this.reflectedPayloads = payloads;
        this.isEditingReflected = false;
      } catch (error) {
        console.error('保存反射型XSS规则失败', error);
        ElMessage.error('保存反射型XSS规则失败');
      }
    },

    async saveStoredPayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.storedPayloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'xss',
          name: '存储型XSS规则',
          description: '用于检测存储型XSS漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'stored',
            payloads: payloads
          })
        };

        console.log("准备保存存储型XSS规则:", ruleData);

        if (this.storedRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.storedRuleId, ruleData);
          ElMessage.success('存储型XSS规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.storedRuleId = response.id;
          ElMessage.success('存储型XSS规则创建成功');
        }

        // 更新显示
        this.storedPayloads = payloads;
        this.isEditingStored = false;
      } catch (error) {
        console.error('保存存储型XSS规则失败', error);
        ElMessage.error('保存存储型XSS规则失败');
      }
    },

    async saveDomPayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.domPayloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'xss',
          name: 'DOM型XSS规则',
          description: '用于检测DOM型XSS漏洞的规则',
          rule_content: JSON.stringify({
            subType: 'dom',
            payloads: payloads
          })
        };

        console.log("准备保存DOM型XSS规则:", ruleData);

        if (this.domRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.domRuleId, ruleData);
          ElMessage.success('DOM型XSS规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.domRuleId = response.id;
          ElMessage.success('DOM型XSS规则创建成功');
        }

        // 更新显示
        this.domPayloads = payloads;
        this.isEditingDom = false;
      } catch (error) {
        console.error('保存DOM型XSS规则失败', error);
        ElMessage.error('保存DOM型XSS规则失败');
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