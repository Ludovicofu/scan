<template>
  <div class="rule-edit-page">
    <h1>{{ isEdit ? '编辑规则' : '新建规则' }}</h1>

    <div class="placeholder-message">
      <el-alert
        title="编辑规则请使用规则管理页面"
        type="info"
        :closable="false"
        description="独立的规则编辑页面尚未实现，请通过规则管理页面添加和修改规则。"
        show-icon
      ></el-alert>
    </div>

    <div class="actions">
      <el-button @click="goBack">返回规则管理</el-button>
    </div>
  </div>
</template>

<script>
export default {
  name: 'RuleEditPage',
  props: {
    id: {
      type: [String, Number],
      default: null
    }
  },
  data() {
    return {
      isEdit: !!this.id
    };
  },
  methods: {
    goBack() {
      this.$router.push('/rules');
    }
  }
};
</script>

<style scoped>
.rule-edit-page {
  padding: 20px;
}

h1 {
  margin-bottom: 20px;
  font-size: 24px;
  color: #303133;
}

.placeholder-message {
  margin-bottom: 20px;
}

.actions {
  margin-top: 20px;
}
</style>