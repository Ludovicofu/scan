<template>
  <el-dialog
    :title="isEdit ? '修改规则' : '新增规则'"
    v-model="dialogVisible"
    width="60%"
    @close="handleClose"
  >
    <el-form :model="form" :rules="rules" ref="ruleForm" label-width="100px">
      <el-form-item label="扫描类型" prop="scan_type">
        <el-radio-group v-model="form.scan_type">
          <el-radio label="passive">被动扫描规则</el-radio>
          <el-radio label="active">主动扫描规则</el-radio>
        </el-radio-group>
      </el-form-item>

      <el-form-item label="描述" prop="description">
        <el-input v-model="form.description" placeholder="请输入规则描述"></el-input>
      </el-form-item>

      <el-form-item v-if="form.scan_type === 'active'" label="行为" prop="behaviors">
        <el-input
          type="textarea"
          v-model="form.behaviors"
          placeholder="请输入行为（访问路径），多个行为按行分割"
          :rows="5"
        ></el-input>
        <div class="form-tip">例如: /console/login/LoginForm.jsp</div>
      </el-form-item>

      <el-form-item label="规则类型" prop="rule_type">
        <el-select v-model="form.rule_type" placeholder="请选择规则类型">
          <el-option label="状态码判断" value="status_code"></el-option>
          <el-option label="响应内容匹配" value="response_content"></el-option>
          <el-option label="HTTP 头匹配" value="header"></el-option>
          <!-- 不在普通表单中提供端口扫描选项，由专用组件管理 -->
        </el-select>
      </el-form-item>

      <el-form-item label="匹配值" prop="match_values">
        <el-input
          type="textarea"
          v-model="form.match_values"
          placeholder="请输入匹配值，多个匹配值按行分割"
          :rows="5"
        ></el-input>
        <div class="form-tip">
          <span v-if="form.rule_type === 'status_code'">例如: 200, 403, 500</span>
          <span v-if="form.rule_type === 'response_content'">例如: WebLogic Server, Apache</span>
          <span v-if="form.rule_type === 'header'">例如: Server: nginx, X-Powered-By: PHP</span>
        </div>
      </el-form-item>
    </el-form>

    <template #footer>
      <div class="dialog-footer">
        <el-button @click="handleClose">取消</el-button>
        <el-button type="primary" @click="submitForm">确定</el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script>
export default {
  name: 'InfoRuleEditDialog',
  props: {
    visible: {
      type: Boolean,
      required: true
    },
    isEdit: {
      type: Boolean,
      default: false
    },
    ruleForm: {
      type: Object,
      required: true
    },
    activeTab: {
      type: String,
      required: true
    }
  },
  emits: ['close', 'submit'],
  data() {
    return {
      dialogVisible: false,
      form: {
        id: null,
        module: '',
        scan_type: 'passive',
        description: '',
        rule_type: 'response_content',
        match_values: '',
        behaviors: ''
      },
      rules: {
        description: [
          { required: true, message: '请输入规则描述', trigger: 'blur' }
        ],
        rule_type: [
          { required: true, message: '请选择规则类型', trigger: 'change' }
        ],
        match_values: [
          { required: true, message: '请输入匹配值', trigger: 'blur' }
        ],
        behaviors: [
          { required: true, message: '请输入行为', trigger: 'blur' }
        ]
      }
    };
  },
  watch: {
    visible(val) {
      this.dialogVisible = val;
      if (val) {
        this.initForm();
      }
    },
    dialogVisible(val) {
      if (!val) {
        this.$emit('close');
      }
    }
  },
  methods: {
    initForm() {
      // 初始化表单数据
      this.form = { ...this.ruleForm };
      this.form.module = this.activeTab;

      // 重置表单验证
      this.$nextTick(() => {
        if (this.$refs.ruleForm) {
          this.$refs.ruleForm.clearValidate();
        }
      });
    },
    handleClose() {
      this.dialogVisible = false;
    },
    async submitForm() {
      try {
        await this.$refs.ruleForm.validate();

        // 准备提交数据
        const formData = {
          module: this.activeTab,
          scan_type: this.form.scan_type,
          description: this.form.description,
          rule_type: this.form.rule_type,
          match_values: this.form.match_values,
          behaviors: this.form.scan_type === 'active' ? this.form.behaviors : null,
          is_enabled: true  // 确保规则是启用的
        };

        // 触发提交事件
        this.$emit('submit', formData);
      } catch (error) {
        // 表单验证失败
        console.error('表单验证失败', error);
      }
    }
  }
};
</script>

<style scoped>
.form-tip {
  font-size: 12px;
  color: #909399;
  margin-top: 5px;
}
</style>