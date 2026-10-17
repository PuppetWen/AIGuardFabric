/* ------------------------------------------------------------------ */
/* Demo security data, split into ./security/* and re-exported here so  */
/* every existing import path keeps working unchanged.                  */
/* ------------------------------------------------------------------ */

export { demoCampaigns, demoCampaignResults, resultsForCampaign, buildCampaignReport } from './security/campaigns';
export { demoPolicies } from './security/policies';
export { demoInterceptPoints, demoInterceptEvents } from './security/interception';
export { demoQuotaUsages, demoBlacklists } from './security/quotas';
export { demoAgentTeams, demoCrossTeamCalls, demoServiceBindings } from './security/agent-teams';
export { demoSelfCheckItems } from './security/self-check';
