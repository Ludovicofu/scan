<template>
  <el-dialog
    title="漏洞详情"
    v-model="dialogVisible"
    width="80%"
    @close="handleClose"
  >
    <div v-if="vulnResult">
      <el-descriptions :column="1" border>
        <el-descriptions-item label="资产">{{ vulnResult.asset_host }}</el-descriptions-item>
        <el-descriptions-item label="漏洞类型">
          {{ vulnResult.vuln_type_display }}
          <el-tag v-if="vulnResult.vuln_subtype" style="margin-left: 10px" size="small">
            {{ getVulnSubtypeDisplay(vulnResult.vuln_subtype) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="漏洞名称">{{ vulnResult.name }}</el-descriptions-item>
        <el-descriptions-item label="URL">{{ vulnResult.url }}</el-descriptions-item>
        <el-descriptions-item v-if="vulnResult.parameter" label="参数">{{ vulnResult.parameter }}</el-descriptions-item>
        <el-descriptions-item v-if="vulnResult.payload" label="Payload">{{ vulnResult.payload }}</el-descriptions-item>
        <el-descriptions-item label="描述">{{ vulnResult.description }}</el-descriptions-item>
        <el-descriptions-item label="漏洞证明">{{ vulnResult.proof }}</el-descriptions-item>
        <el-descriptions-item label="扫描日期">{{ formatDate(vulnResult.scan_date) }}</el-descriptions-item>
        <el-descriptions-item label="验证状态">
          <el-tag :type="vulnResult.is_verified ? 'success' : 'info'">
            {{ vulnResult.is_verified ? '已验证' : '未验证' }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <el-divider content-position="left">请求/响应详情</el-divider>
      <div class="http-details">
        <el-tabs>
          <el-tab-pane label="HTTP请求">
            <div class="detail-panel">
              <!-- 显示完整的请求数据，使用pre标签保留格式 -->
              <pre class="http-content">{{ formatHttpRequest(vulnResult.request) }}</pre>

              <!-- 如果有参数和载荷，高亮显示 -->
              <div v-if="vulnResult.parameter && vulnResult.payload" class="highlight-section">
                <div class="highlight-title">注入点:</div>
                <div class="highlight-content">
                  参数 <span class="param-highlight">{{ vulnResult.parameter }}</span>
                  载荷 <span class="payload-highlight">{{ vulnResult.payload }}</span>
                </div>
              </div>
            </div>
          </el-tab-pane>
          <el-tab-pane label="HTTP响应">
            <div class="detail-panel">
              <!-- 根据漏洞类型使用不同的高亮方法 -->
              <div v-if="vulnType === 'sql_injection'" v-html="highlightSqlError(vulnResult.response, vulnResult.proof)"></div>
              <div v-else-if="vulnType === 'xss'" v-html="highlightXssPayload(vulnResult.response, vulnResult.payload)"></div>
              <div v-else-if="vulnType === 'command_injection'" v-html="highlightRceOutput(vulnResult.response, vulnResult.proof)"></div>
              <div v-else-if="vulnType === 'ssrf'" v-html="highlightSsrfResponse(vulnResult.response, vulnResult.proof)"></div>
              <div v-else>
                <pre class="http-content">{{ formatHttpResponse(vulnResult.response) }}</pre>
              </div>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞详情" v-if="vulnResult.proof">
            <div class="detail-panel">
              <div class="highlight-section">
                <div class="highlight-title">漏洞证明:</div>
                <div class="highlight-content">{{ vulnResult.proof }}</div>
              </div>

              <!-- 漏洞类型特定信息 -->
              <div class="vuln-details">
                <component
                  :is="getVulnDetailsComponent()"
                  :vulnResult="vulnResult"
                  v-if="getVulnDetailsComponent()"
                ></component>
                <div v-else>
                  <h4>{{ vulnResult.vuln_type_display }} 漏洞信息</h4>
                  <p>{{ getVulnDescription() }}</p>
                </div>
              </div>
            </div>
          </el-tab-pane>
          <el-tab-pane label="复现" v-if="hasExploitTab()">
            <div class="detail-panel">
              <div class="highlight-section">
                <div class="highlight-title">复现方法:</div>
                <div class="highlight-content">
                  <p>1. 向以下URL发送请求: <code>{{ vulnResult.url }}</code></p>
                  <p v-if="vulnResult.parameter">2. 修改参数 <code>{{ vulnResult.parameter }}</code> 的值为: <code class="payload-highlight">{{ vulnResult.payload }}</code></p>
                  <p>3. 观察响应中的异常信息或行为</p>

                  <!-- SQL注入特定复现信息 -->
                  <template v-if="vulnType === 'sql_injection'">
                    <p>4. 可使用以下SQL注入工具进行更深入验证:</p>
                    <ul>
                      <li>SQLmap: <code>sqlmap -u "{{ buildSqlmapUrl(vulnResult) }}" --batch</code></li>
                      <li>Burp Suite: 使用Intruder模块进行参数Fuzz测试</li>
                    </ul>
                  </template>

                  <!-- XSS特定复现信息 -->
                  <template v-else-if="vulnType === 'xss'">
                    <p>4. 可尝试使用以下XSS Payload进行进一步验证:</p>
                    <ul>
                      <li><code>&lt;script&gt;alert(document.domain)&lt;/script&gt;</code></li>
                      <li><code>&lt;img src=x onerror=alert(document.cookie)&gt;</code></li>
                    </ul>
                  </template>

                  <!-- RCE特定复现信息 -->
                  <template v-else-if="vulnType === 'command_injection'">
                    <p>4. 可尝试执行以下命令进行验证:</p>
                    <ul>
                      <li>Linux: <code>id</code>, <code>uname -a</code>, <code>cat /etc/passwd</code></li>
                      <li>Windows: <code>whoami</code>, <code>ipconfig</code>, <code>dir</code></li>
                    </ul>
                  </template>

                  <!-- SSRF特定复现信息 -->
                  <template v-else-if="vulnType === 'ssrf'">
                    <p>4. 可尝试访问以下资源进行验证:</p>
                    <ul>
                      <li>内网IP: <code>http://192.168.0.1/</code>, <code>http://10.0.0.1/</code></li>
                      <li>本地服务: <code>http://localhost:8080/</code>, <code>http://127.0.0.1:3306/</code></li>
                      <li>文件协议: <code>file:///etc/passwd</code>, <code>file:///C:/Windows/win.ini</code></li>
                    </ul>
                  </template>
                </div>
              </div>
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="handleClose">关闭</el-button>
        <el-button v-if="vulnResult && !vulnResult.is_verified"
                 type="success"
                 @click="verifyVulnerability(vulnResult.id)">验证</el-button>
      </span>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'VulnDetailDialog',
  props: {
    visible: {
      type: Boolean,
      required: true
    },
    vulnResult: {
      type: Object,
      default: null
    },
    vulnType: {
      type: String,
      default: ''
    }
  },
  emits: ['close', 'verify'],
  computed: {
    dialogVisible: {
      get() {
        return this.visible;
      },
      set(value) {
        if (!value) {
          this.$emit('close');
        }
      }
    }
  },
  methods: {
    handleClose() {
      this.$emit('close');
    },

    verifyVulnerability(id) {
      this.$emit('verify', id);
    },

    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    },

    // 格式化HTTP请求
    formatHttpRequest(request) {
      if (!request) return '无请求数据';

      // 如果请求不是以HTTP开头，尝试添加前缀
      if (!request.startsWith('GET') && !request.startsWith('POST') && !request.startsWith('HTTP')) {
        // 推测并补充HTTP方法
        const url = this.vulnResult ? this.vulnResult.url : '';
        const method = url.includes('?') ? 'GET' : 'POST';
        return `${method} ${url} HTTP/1.1\nHost: ${new URL(url).hostname}\n\n${request}`;
      }

      return request;
    },

    // 格式化HTTP响应
    formatHttpResponse(response) {
      if (!response) return '无响应数据';

      // 如果响应不是以HTTP开头，尝试添加前缀
      if (!response.startsWith('HTTP')) {
        return `HTTP/1.1 200 OK\n\n${response}`;
      }

      return response;
    },

    // 高亮SQL错误信息
    // eslint-disable-next-line no-unused-vars
    highlightSqlError(response, proofText) {
      if (!response || !proofText) return '<pre class="http-content">无响应数据</pre>';

      let responseText = this.formatHttpResponse(response);
      // 先将HTML特殊字符转义，防止XSS攻击
      responseText = this.escapeHtml(responseText);

      // 从证明中提取错误关键词
      const errorKeywords = this.extractErrorKeywords(proofText);

      // 如果没有关键词，返回原始响应
      if (errorKeywords.length === 0) {
        return `<pre class="http-content">${responseText}</pre>`;
      }

      // 高亮显示错误关键词
      for (const keyword of errorKeywords) {
        if (keyword.length < 3) continue; // 跳过太短的关键词

        try {
          // 创建一个忽略大小写的正则表达式
          const regex = new RegExp(`(${this.escapeRegExp(keyword)})`, 'gi');

          // 替换为高亮的HTML
          responseText = responseText.replace(
            regex,
            '<span class="sql-error-highlight">$1</span>'
          );
        } catch (e) {
          console.error('高亮关键词出错:', e);
        }
      }

      return `<pre class="http-content">${responseText}</pre>`;
    },

    // 高亮XSS Payload
    // eslint-disable-next-line no-unused-vars
    highlightXssPayload(response, payload) {
      if (!response || !payload) return '<pre class="http-content">无响应数据</pre>';

      let responseText = this.formatHttpResponse(response);
      // 转义HTML，防止XSS攻击
      responseText = this.escapeHtml(responseText);

      // 转义Payload中的特殊字符，用于正则表达式
      const escapedPayload = this.escapeRegExp(payload);

      try {
        // 创建正则表达式，匹配payload
        const regex = new RegExp(`(${escapedPayload})`, 'gi');

        // 替换为高亮的HTML
        responseText = responseText.replace(
          regex,
          '<span class="xss-payload-highlight">$1</span>'
        );

        // 尝试匹配HTML标签
        const tagRegex = /(&lt;[^&]*&gt;)/g;
        responseText = responseText.replace(
          tagRegex,
          '<span class="html-tag-highlight">$1</span>'
        );
      } catch (e) {
        console.error('高亮XSS Payload出错:', e);
      }

      return `<pre class="http-content">${responseText}</pre>`;
    },

    // 高亮RCE命令输出
    // eslint-disable-next-line no-unused-vars
    highlightRceOutput(response, proofText) {
      if (!response) return '<pre class="http-content">无响应数据</pre>';

      let responseText = this.formatHttpResponse(response);
      // 转义HTML，防止XSS攻击
      responseText = this.escapeHtml(responseText);

      // 从proofText中提取执行结果的关键词
      const outputMatch = proofText ? proofText.match(/执行结果[:：]\s*(.+?)(?=\s*$|\s*[，。,.])/i) : null;

      if (outputMatch && outputMatch[1]) {
        try {
          // 创建正则表达式，匹配输出结果
          const regex = new RegExp(`(${this.escapeRegExp(outputMatch[1])})`, 'gi');

          // 替换为高亮的HTML
          responseText = responseText.replace(
            regex,
            '<span class="rce-output-highlight">$1</span>'
          );
        } catch (e) {
          console.error('高亮RCE输出出错:', e);
        }
      }

      return `<pre class="http-content">${responseText}</pre>`;
    },

    // 高亮SSRF响应
    // eslint-disable-next-line no-unused-vars
    highlightSsrfResponse(response, proofText) {
      if (!response) return '<pre class="http-content">无响应数据</pre>';

      let responseText = this.formatHttpResponse(response);
      // 转义HTML，防止XSS攻击
      responseText = this.escapeHtml(responseText);

      // 如果是文件协议的SSRF，尝试高亮文件内容
      if (this.vulnResult && this.vulnResult.vuln_subtype === 'file_protocol') {
        try {
          // 高亮文件内容的特征
          const filePatterns = [
            /(\[.*?\])/g,  // INI文件的节
            /(root:.*?:)/g,  // /etc/passwd中的root行
            /(&lt;!DOCTYPE.*?&gt;)/g,  // DOCTYPE声明
            /(&lt;html.*?&gt;)/g  // HTML标签
          ];

          for (const pattern of filePatterns) {
            responseText = responseText.replace(
              pattern,
              '<span class="ssrf-file-highlight">$1</span>'
            );
          }
        } catch (e) {
          console.error('高亮文件内容出错:', e);
        }
      } else {
        // 尝试高亮IP地址和端口
        try {
          const ipPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?)/g;
          responseText = responseText.replace(
            ipPattern,
            '<span class="ssrf-ip-highlight">$1</span>'
          );
        } catch (e) {
          console.error('高亮IP地址出错:', e);
        }
      }

      return `<pre class="http-content">${responseText}</pre>`;
    },

    // 提取错误关键词
    extractErrorKeywords(proofText) {
      const keywords = [];

      // 从漏洞证明中提取关键词
      if (proofText) {
        // 尝试提取包含"SQL错误信息"后面的内容
        const errorMatch = proofText.match(/包含SQL错误信息[:：]\s*(.+)/i);
        if (errorMatch && errorMatch[1]) {
          const errorInfo = errorMatch[1].trim();
          // 拆分可能的多个关键词
          errorInfo.split(/[,，;；\s]+/).forEach(keyword => {
            if (keyword && keyword.length > 3) { // 只添加有意义的关键词
              keywords.push(keyword);
            }
          });
        }

        // 尝试直接从proofText中提取常见SQL错误关键词
        const commonPatterns = [
          "SQL syntax", "MySQL", "SQL Server", "ORA-", "SQLSTATE",
          "syntax error", "mysqli", "Warning"
        ];

        for (const pattern of commonPatterns) {
          if (proofText.includes(pattern)) {
            keywords.push(pattern);
          }
        }
      }

      // 如果从证明中提取不到关键词，添加常见的SQL错误关键词
      if (keywords.length === 0) {
        keywords.push(
          "SQL syntax", "MySQL", "SQLSTATE", "ORA-", "SQL Server",
          "Warning", "mysqli", "syntax error"
        );
      }

      return keywords;
    },

    // 构建SQLmap URL
    buildSqlmapUrl(result) {
      if (!result || !result.url) return '';

      if (result.parameter) {
        // 如果有参数信息，构建带参数的URL
        const urlObj = new URL(result.url);
        if (!urlObj.searchParams.has(result.parameter)) {
          // 如果URL中没有该参数，添加一个占位符
          urlObj.searchParams.set(result.parameter, '*');
        } else {
          // 标记该参数为注入点
          const paramValue = urlObj.searchParams.get(result.parameter);
          urlObj.searchParams.set(result.parameter, paramValue + '*');
        }
        return urlObj.toString();
      }

      // 如果没有参数信息，返回原始URL
      return result.url;
    },

    // 转义正则表达式中的特殊字符
    escapeRegExp(string) {
      return string ? string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : ''; // $& 表示整个匹配的字符串
    },

    // 转义HTML，防止XSS攻击
    escapeHtml(unsafe) {
      if (!unsafe) return '';
      return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    },

    // 获取漏洞子类型显示名称
    getVulnSubtypeDisplay(subtype) {
      const subtypeMap = {
        // SQL注入子类型
        'error_based': '回显型',
        'blind': '盲注型',
        'time_based': '时间盲注型',
        'boolean_based': '布尔盲注型',
        'stacked_queries': '堆叠查询型',
        'out_of_band': '带外型',

        // XSS子类型
        'stored': '存储型',
        'reflected': '反射型',
        'dom': 'DOM型',

        // 文件包含子类型
        'lfi': '本地文件包含',
        'rfi': '远程文件包含',

        // 命令注入子类型
        'os_command': '系统命令',
        'blind_os_command': '盲命令',
        'php_code': 'PHP代码',
        'java_code': 'Java代码',
        'python_code': 'Python代码',

        // SSRF子类型
        'internal_network': '内网访问',
        'file_protocol': '文件协议',
        'blind_ssrf': '盲SSRF',
        'dns_rebinding': 'DNS重绑定',

        // HTTP头注入
        'http_header': 'HTTP头注入'
      };
      return subtypeMap[subtype] || subtype;
    },

    // 获取漏洞类型对应的详情组件
    getVulnDetailsComponent() {
      // 这里可以根据漏洞类型返回不同的组件
      // 实际项目中可以实现专门的详情组件
      return null;
    },

    // 获取漏洞描述
    getVulnDescription() {
      // 根据漏洞类型返回不同的描述
      const vulnTypeDescMap = {
        'sql_injection': 'SQL注入漏洞是指攻击者能够通过在输入参数中注入SQL代码，影响应用程序与数据库的交互，从而可能导致数据泄露、数据篡改或绕过认证等安全问题。',
        'xss': '跨站脚本(XSS)漏洞是指攻击者能够向网页注入恶意脚本代码，当其他用户浏览该页面时，这些脚本会在用户的浏览器中执行，可能导致会话劫持、敏感信息泄露或网页篡改等问题。',
        'command_injection': '命令注入漏洞是指攻击者能够通过在输入参数中注入操作系统命令，使应用程序执行这些命令，从而可能获取服务器控制权、读取敏感文件或执行其他恶意操作。',
        'ssrf': '服务器端请求伪造(SSRF)漏洞是指攻击者能够利用服务器发起请求，访问内部网络资源或外部服务，可能导致信息泄露、内网探测或绕过防火墙限制等问题。',
        'file_inclusion': '文件包含漏洞是指攻击者能够利用应用程序包含远程或本地文件的功能，从而导致任意文件读取、代码执行或服务器信息泄露等安全问题。'
      };

      return vulnTypeDescMap[this.vulnType] || '该漏洞可能导致系统安全风险，建议及时修复。';
    },

    // 判断是否显示复现标签页
    hasExploitTab() {
      // 常见漏洞类型都可以显示复现标签页
      const exploitTypes = ['sql_injection', 'xss', 'command_injection', 'ssrf', 'file_inclusion'];
      return exploitTypes.includes(this.vulnType);
    }
  }
};
</script>

<style scoped>
.http-details {
  margin-top: 15px;
}

.detail-panel {
  background-color: #f5f7fa;
  padding: 10px;
  border-radius: 4px;
  margin-top: 10px;
}

.detail-panel pre {
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: monospace;
  font-size: 13px;
  padding: 10px;
  border-radius: 4px;
  max-height: 500px;
  overflow-x: auto;
  overflow-y: auto;
  background-color: #2d2d2d;
  color: #f8f8f2;
}

.http-content {
  line-height: 1.5;
  margin: 0;
}

.highlight-section {
  margin-bottom: 10px;
  background-color: #ebeef5;
  padding: 10px;
  border-radius: 4px;
}

.highlight-title {
  font-weight: bold;
  margin-bottom: 5px;
  color: #303133;
}

.highlight-content {
  font-family: Consolas, Monaco, 'Andale Mono', monospace;
  font-size: 13px;
  line-height: 1.6;
}

/* 参数和Payload高亮样式 */
.param-highlight {
  background-color: #409EFF;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
}

.payload-highlight {
  background-color: #F56C6C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-family: monospace;
}

/* 漏洞类型特定高亮 */
:deep(.sql-error-highlight) {
  background-color: #F56C6C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

:deep(.xss-payload-highlight) {
  background-color: #E6A23C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

:deep(.html-tag-highlight) {
  color: #67C23A;
  font-weight: bold;
}

:deep(.rce-output-highlight) {
  background-color: #67C23A;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

:deep(.ssrf-ip-highlight) {
  background-color: #409EFF;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

:deep(.ssrf-file-highlight) {
  background-color: #E6A23C;
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

/* HTTP内容样式改进 */
.detail-panel :deep(pre.http-content) {
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: monospace;
  font-size: 13px;
  padding: 10px;
  border-radius: 4px;
  max-height: 500px;
  overflow-x: auto;
  overflow-y: auto;
  background-color: #2d2d2d;
  color: #f8f8f2;
  line-height: 1.5;
  margin: 0;
}

.vuln-details {
  margin-top: 20px;
  padding: 15px;
  background-color: #f0f9eb;
  border-radius: 4px;
  border-left: 4px solid #67C23A;
}

.vuln-details h4 {
  margin-top: 0;
  margin-bottom: 10px;
  color: #67C23A;
}

.vuln-details p {
  margin: 5px 0;
  line-height: 1.6;
}
</style>