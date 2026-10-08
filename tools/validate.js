// Semantic KQL validation against the table schemas these queries use (Kusto.Language parser).
// Usage: node tools/validate.js queries/*.kql
const fs=require('fs');
global.Bridge = require('@kusto/language-service-next/bridge.js');
require('@kusto/language-service-next/Kusto.Language.Bridge.js');
const K = global.Kusto.Language;
const S = K.Symbols;
const schemas = {
 SigninLogs: "(TimeGenerated:datetime, UserPrincipalName:string, AppDisplayName:string, IPAddress:string, ResultType:string, AuthenticationProtocol:string, LocationDetails:dynamic, RiskLevelDuringSignIn:string, RiskState:string, RiskEventTypes_V2:string, UserAgent:string, ConditionalAccessStatus:string)",
 AADNonInteractiveUserSignInLogs: "(TimeGenerated:datetime, UserPrincipalName:string, AppDisplayName:string, IPAddress:string, ResultType:string, AuthenticationProtocol:string, LocationDetails:string, UserAgent:string)",
 AuditLogs: "(TimeGenerated:datetime, OperationName:string, LoggedByService:string, TargetResources:dynamic, InitiatedBy:dynamic, ResultReason:string, Result:string, AdditionalDetails:dynamic, CorrelationId:string)",
 CloudAppEvents: "(Timestamp:datetime, Application:string, ActionType:string, RawEventData:dynamic, AccountDisplayName:string, AccountObjectId:string, IPAddress:string, CountryCode:string)",
 DeviceProcessEvents: "(Timestamp:datetime, DeviceName:string, AccountName:string, InitiatingProcessFileName:string, InitiatingProcessCommandLine:string, InitiatingProcessAccountName:string, FileName:string, FolderPath:string, ProcessCommandLine:string, SHA256:string, ReportId:long, DeviceId:string)",
};
const tables = Object.entries(schemas).map(([n,s]) => new S.TableSymbol.$ctor7(n, s, null));
const db = new S.DatabaseSymbol.$ctor2("db", null, tables);
const cl = new S.ClusterSymbol.ctor("c", [db]); let globals = K.GlobalState.Default.WithCluster(cl).WithDatabase(db);
let bad=0;
for (const f of process.argv.slice(2)) {
  const text = fs.readFileSync(f,'utf8');
  const code = K.KustoCode.ParseAndAnalyze(text, globals);
  const diags = code.GetDiagnostics();
  const n = diags.Count;
  const errs=[];
  for (let i=0;i<n;i++){ const d=diags.getItem(i); errs.push(`${d.Severity} ${d.Code} @${d.Start}: ${d.Message} [${text.substr(d.Start, Math.max(d.Length,1)).slice(0,40)}]`); }
  console.log((n? 'FAIL ':'OK   ')+f); errs.forEach(e=>console.log('   '+e)); bad+=n;
}
process.exit(bad?1:0);
