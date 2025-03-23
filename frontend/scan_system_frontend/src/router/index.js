import { createRouter, createWebHistory } from 'vue-router';
import HomePage from '@/views/HomePage.vue';
import InfoResultsPage from '@/views/InfoResultsPage.vue';
import VulnResultsPage from '@/views/VulnResultsPage.vue';
import RulesPage from '@/views/RulesPage.vue';
import RuleEditPage from '@/views/RuleEditPage.vue';
import SettingsPage from '@/views/SettingsPage.vue';

const routes = [
  {
    path: '/',
    name: 'Home',
    component: HomePage
  },
  {
    path: '/info-results',
    name: 'InfoResults',
    component: InfoResultsPage
  },
  {
    path: '/vuln-results',
    name: 'VulnResults',
    component: VulnResultsPage
  },
  {
    path: '/rules',
    name: 'Rules',
    component: RulesPage
  },
  {
    path: '/rules/edit/:id?',
    name: 'RuleEdit',
    component: RuleEditPage,
    props: true
  },
  {
    path: '/settings',
    name: 'Settings',
    component: SettingsPage
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/'
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes
});

export default router;