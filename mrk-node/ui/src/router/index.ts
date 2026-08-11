import { createRouter, createWebHistory } from 'vue-router'
import OverviewPage from '../pages/OverviewPage.vue'
import BlocksPage from '../pages/BlocksPage.vue'
import CheckpointsPage from '../pages/CheckpointsPage.vue'
import BlockPage from '../pages/BlockPage.vue'
import OperationPage from '../pages/OperationPage.vue'
import AccountPage from '../pages/AccountPage.vue'
import AccountsPage from '../pages/AccountsPage.vue'
import NodesPage from '../pages/NodesPage.vue'
import NodePage from '../pages/NodePage.vue'
import GovernancePage from '../pages/GovernancePage.vue'
import ProposalPage from '../pages/ProposalPage.vue'
import TreasuryPage from '../pages/TreasuryPage.vue'
import NotFoundPage from '../pages/NotFoundPage.vue'

export const router = createRouter({
  history: createWebHistory('/explorer/'),
  scrollBehavior: () => ({ top: 0 }),
  routes: [
    { path: '/', component: OverviewPage },
    { path: '/blocks', component: BlocksPage },
    { path: '/checkpoints', component: CheckpointsPage },
    { path: '/blocks/:height', component: BlockPage },
    { path: '/operations/:id', component: OperationPage },
    { path: '/accounts', component: AccountsPage },
    { path: '/accounts/:address', component: AccountPage },
    { path: '/nodes', component: NodesPage },
    { path: '/nodes/:id', component: NodePage },
    { path: '/governance', component: GovernancePage },
    { path: '/governance/:id', component: ProposalPage },
    { path: '/treasury', component: TreasuryPage },
    { path: '/:pathMatch(.*)*', component: NotFoundPage },
  ],
})
