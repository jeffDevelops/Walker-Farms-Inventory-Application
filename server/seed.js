/* jshint esversion: 6 */
const csvParser = require('papaparse');

const mongoose = require('mongoose');
const db = require('./models');
// mongoose.set('debug', true);
mongoose.Promise = Promise;



//////////////////////////////////////////

let useCaseList = [
  {
    useCase: `SEP - anomalous new listening port - critical user Should we change this to confirm to priority chart? WAS Anomalous New Listening Port - ECS -->`,
    domain: `Endpoint`,
    spl: `index=ecat_network |stats count by port |rare port| sort -port`,
    comments: ``
  },
  {
    useCase: `SEP - Anomalous New Listening Port WAS Anomalous New Listening Port`,
    domain: `Endpoint`,
    spl: `"|tstats summariesonly=t count FROM datamodel=Malware where nodename=Malware.Allowed_Malware groupby Malware_Attacks.user Malware_Attacks.src actual_action disposition downloaded_by hash_value Malware_Attacks.signature
|tstats prestats=t append=t count FROM datamode=Authentication where nodename=Privileged_Authentication groupby Authentication.user"`,
    comments: ``
  },
  {
    useCase: `AD - Windows system event logs cleared`,
    domain: `Endpoint`,
    spl: `|datamodel Malware Allowed_Malware search |search [| inputlookup auth_privileged.csv | fields + identity | rename identity AS Malware_Attacks.user] | table _time Malware_Attacks.user Malware_Attacks.src actual_action disposition downloaded_by hash_value Malware_Attacks.signature _raw`,
    comments: `Event logs have been cleared on [CUSTOMER]-AD server.`
  },
  {
    useCase: `SEP  - logon to infected machine - critical user. Should we change this to confirm to priority chart? WAS High or Critical Priority Individual Logging into Infected Machine`,
    domain: `Endpoint`,
    spl: `index="ad" sourcetype="Snare:Security" EventCode="4624" [search index="symantec" sourcetype="sep12:risk" (action="deferred" OR action="allowed") | dedup dest_nt_host | rename dest_nt_host as Workstation_Name | table Workstation_Name] | search [|inputlookup _identities | makemv delim="|" category | where category="ecs_user" | eval User="*".identity | table User] | stats count sparkline values(user) as Users by Workstation_Name`,
    comments: `Access - [CUSTOMER]-AD - critical user logging into infected machine`
  },
  {
    useCase: `SEP - Logins to infected workstations - $ accounts`,
    domain: `Endpoint`,
    spl: `| tstats allow_old_summaries=true dc(All_Application_State.Ports.transport_dest_port) as "port_count" from datamodel=Application_State where   nodename=All_Application_State.Ports  by "All_Application_State.dest"  | rename "All_Application_State.dest" as "dest" | where 'port_count'>20`,
    comments: `[CUSTOMER]-AD administrators logon to system that is malware infected according to SEP.`
  },
  {
    useCase: `SEP - Logins to infected workstations - domain admins`,
    domain: `Endpoint`,
    spl: `| tstats summariesonly=t allow_old_summaries=true count from datamodel=Network_Traffic by All_Traffic.dest_port | \`drop_dm_object_name("All_Traffic")\` | localop | xswhere count from count_by_dest_port_1d in network_traffic by dest_port is extreme | sort - count`,
    comments: `[CUSTOMER]-AD administrators logon to system that is malware infected according to SEP.`
  },
  {
    useCase: `SEP - anomalous new process - critical user. Should we change this to confirm to priority chart? WAS Anomalous New Process - ECS`,
    domain: `Endpoint`,
    spl: `index=ecat_process |stats count by process_path |sort -count |rare process_path`,
    comments: `Could indicate malware . Marginal at best. Better to use Cybereason.`
  },
  {
    useCase: `SEP - Host with excessive listening ports`,
    domain: `Endpoint`,
    spl: ``,
    comments: `Indicate when a system owner by a critical user has a high number of listening ports.`
  },
  {
    useCase: `"Endpoint - SEP - Host with excessive listening ports - critical user. Should we change this to confirm to priority chart?"`,
    domain: `Endpoint`,
    spl: `index=ecat_network |stats count(port) by machine | sort -count(port)`,
    comments: `For systems with ECAT installed, list out sorted by ports? Unsure if this is listening ports.`
  },
  {
    useCase: `SEP - Copies to USB - file includes DLP tag`,
    domain: `Endpoint`,
    spl: `index=symantec api="File Write" sourcetype="sep12:behavior" username=loomad earliest=-1y | rex field=message "^.*Device ID: (?<usb_device>.*)$" | table _time,parame`,
    comments: `Indicate when a user copies DLP tagged files to USB.`
  },
  {
    useCase: `SEP - Excessive client firewall denies`,
    domain: `Endpoint`,
    spl: `index=symantec sourcetype="sep12:traffic" action=blocked inbound|stats count by user|sort -count`,
    comments: `Hosts running SEP with high amount of inbound blocked connections.`
  },
  {
    useCase: `SEP - Excessive client firewall denies - critical user`,
    domain: `Endpoint`,
    spl: `| tstats summariesonly=t allow_old_summaries=true estdc(Malware_Attacks.dest) as "infected_hosts" from datamodel=Malware where   nodename=Malware_Attacks    | where 'infected_hosts'>100 | eval const_dedup_id="const_dedup_id"`,
    comments: `Hosts running SEP with high amount of inbound blocked connections.`
  },
  {
    useCase: `SEP - Excessive copies to USB - critical user - insider threat`,
    domain: `Endpoint`,
    spl: `| tstats allow_old_summaries=true estdc(Malware_Attacks.dest) as "infected_hosts" from datamodel=Malware where   nodename=Malware_Attacks    | where 'infected_hosts'>100 | eval const_dedup_id="const_dedup_id"`,
    comments: `Systems / users with high amount of copies to USB.`
  },
  {
    useCase: `SEP - Excessive copies to USB - critical user - insider threat`,
    domain: `Endpoint`,
    spl: `| tstats allow_old_summaries=true dc(All_Application_State.Services.service) as "service_count" from datamodel=Application_State where   nodename=All_Application_State.Services  by "All_Application_State.dest" | rename "All_Application_State.dest" as "dest" | where 'service_count'>100`,
    comments: `Systems / users with high amount of copies to USB. - Critical user`
  },
  {
    useCase: `SEP - Excessive hosts not updating AV signatures`,
    domain: `Endpoint`,
    spl: ``,
    comments: `Leading indicator of future malware issues.`
  },
  {
    useCase: `SEP - high number of infected hosts`,
    domain: `Endpoint`,
    spl: `| datamodel Application_State Processes search | \`drop_dm_object_name("All_Application_State")\` | \`drop_dm_object_name("Processes")\` | \`get_interesting_processes\` | search is_prohibited=true | \`get_event_id\` | \`map_notable_fields\` | fields + orig_event_id,orig_raw,dest,process,note`,
    comments: `Endpoint - SEP - high number of infected hosts`
  },
  {
    useCase: `SEP - host with high number of services WAS High Number Of Services`,
    domain: `Endpoint`,
    spl: `| tstats summariesonly=t allow_old_summaries=true dc(Malware_Attacks.signature) as "infection_count" from datamodel=Malware where   nodename=Malware_Attacks  by "Malware_Attacks.dest"  | rename "Malware_Attacks.dest" as "dest" | where 'infection_count'>2`,
    comments: `Unknown, need to understand what this identifies.`
  },
  {
    useCase: `SEP - Logins to infected workstations - privileged accounts`,
    domain: `Endpoint`,
    spl: ``,
    comments: `[CUSTOMER]-AD administrators logon to system that is malware infected according to SEP.`
  },
  {
    useCase: `SEP - prohibited process detected  - critical system`,
    domain: `Endpoint`,
    spl: ``,
    comments: `Instances of 'bad' processes that have attempted to run on critical systems.`
  },
  {
    useCase: `SEP - Host with multiple infections`,
    domain: `Endpoint`,
    spl: ``,
    comments: `Indicates user that has multiple malware infections.`
  },
  {
    useCase: `SEP - Host with multiple infections - critical user`,
    domain: `Endpoint`,
    spl: `| tstats summariesonly=t allow_old_summaries=true dc(Malware_Attacks.date) as "day_count",count from datamodel=Malware where   nodename=Malware_Attacks  by "Malware_Attacks.dest","Malware_Attacks.signature"  | rename "Malware_Attacks.dest" as "dest","Malware_Attacks.signature" as "signature" | where 'day_count'>3`,
    comments: `Indicates user that has multiple malware infections.`
  },
  {
    useCase: `SEP - Host with old AV definitions`,
    domain: `Endpoint`,
    spl: `| tstats \`summariesonly\` max(_time) as lastTime from datamodel=Malware by Malware_Attacks.signature,Malware_Attacks.dest | \`drop_dm_object_name("Malware_Attacks")\` | lookup local=true malware_tracker dest,signature OUTPUT firstTime | eval dayDiff=round((lastTime-firstTime)/86400,1) | search dayDiff>30`,
    comments: `Splunk ES dashboard for Malware Operations. One panel shows virus definition version.`
  },
  {
    useCase: `SEP - Host with old AV definitions - critical user`,
    domain: `Endpoint`,
    spl: `| datamodel "Malware" "Malware_Attacks" search | where ('Malware_Attacks.dest_priority'="high" OR 'Malware_Attacks.dest_priority'="critical") | stats max(_time) as "lastTime",latest(_raw) as "orig_raw",values(Malware_Attacks.dest_priority) as "dest_priority",count by "Malware_Attacks.dest","Malware_Attacks.signature" | rename "Malware_Attacks.dest" as "dest","Malware_Attacks.signature" as "signature"`,
    comments: `Splunk ES dashboard for Malware Operations. One panel shows virus definition version.`
  },
  {
    useCase: `SEP - host with recurring malware infection `,
    domain: `Endpoint`,
    spl: `| tstats summariesonly=t allow_old_summaries=true dc(Malware_Attacks.dest) as "system_count" from datamodel=Malware where   nodename=Malware_Attacks  by "Malware_Attacks.signature"  | rename "Malware_Attacks.signature" as "signature" | where 'system_count'>10`,
    comments: `Splunk ES dashboard. Not specific to 'virus outbreak.'`
  },
  {
    useCase: `SEP - hosts with old malware infection`,
    domain: `Endpoint`,
    spl: `|tstats summariesonly=t count from datamodel=Malware where nodename=Malware.Allowed_Malware (actual_action="Left Alone") by Malware_Attacks.user Malware_Attacks.dest dest_ip hash_value | where count > 0 | sort -count`,
    comments: ``
  },
  {
    useCase: `SEP - malware detected on critical or high system`,
    domain: `Endpoint`,
    spl: `NOT sourcetype=stash \`service\` | \`get_interesting_services\` | search is_prohibited=true | \`get_event_id\` | \`map_notable_fields\` | fields + orig_event_id,orig_raw,dest,service,note`,
    comments: `Critical host with malware`
  },
  {
    useCase: `SEP - malware outbreak`,
    domain: `Endpoint`,
    spl: `"|tstats summariesonly=t count from datamodel=Malware where nodename=Malware.Allowed_Malware (actual_action=""Left Alone"")
|join type=inner Malware_Attacks.user[|inputlookup _identities.csv | search priority=high OR priority=critical | fields + identity | rename identity AS Malware_Attacks.user]
 by Malware_Attacks.user Malware_Attacks.dest dest_ip hash_value | where count > 0 | sort -count"`,
    comments: `Splunk ES dashboard. Not specific to 'virus outbreak.'`
  },
  {
    useCase: `SEP - 1st / 2nd cleaning attempts failed`,
    domain: `Endpoint`,
    spl: `| tstats allow_old_summaries=true sum(Web.bytes_out) as "bytes_out" from datamodel=Web where   nodename=Web "Web.bytes_out">0 AND ("Web.src_priority"="high" OR "Web.src_priority"="critical") by "Web.src","Web.dest" | rename "Web.src" as "src","Web.dest" as "dest" | where 'bytes_out'>10485760`,
    comments: `Indicates when AV is unable to clean malware.`
  },
  {
    useCase: `SEP - prohibited service detected - critical systems`,
    domain: `Endpoint`,
    spl: ``,
    comments: `Instances of 'bad' services that have attempted to run via SEP on critical systems.`
  },
  {
    useCase: `SEP - 1st / 2nd cleaning attempts failed  - critical user`,
    domain: `Endpoint`,
    spl: ``,
    comments: `Indicates when AV is unable to clean malware on critical systems.`
  },
  {
    useCase: `SEP - prohibitied service detected WAS Prohibited Service Detected`,
    domain: `Endpoint`,
    spl: `"tstats allow_old_summaries=true count from datamodel=Network_Resolution where nodename=DNS ""DNS.message_type""=""QUERY"" by ""DNS.src"" | rename ""DNS.src"" as ""src""
| join src type=inner [|inputlookup _assets.csv | search priority=high OR priority=critical | rename ip as ""src""]
|where 'count'>100"`,
    comments: `Instances of 'bad' services that have attempted to run via SEP.`
  },
  {
    useCase: `Network - PAN - high Internet traffic from hosts with malware - critical host`,
    domain: `Endpoint`,
    spl: `| tstats allow_old_summaries=true count from datamodel=Network_Resolution where   nodename=DNS "DNS.message_type"="QUERY" by "DNS.src" | rename "DNS.src" as "src" | where 'count'>100`,
    comments: `[CUSTOMER]Net IPs / users with connections where bytes sent > bytes received * 10 that have also been identified by SEP as having malware, sorted by bytes. Critical systems.`
  },
  {
    useCase: `Network - PAN - high outbound traffic from hosts with malware (SEP)`,
    domain: `Endpoint`,
    spl: ``,
    comments: `[CUSTOMER]Net IPs / users with connections where bytes sent > bytes received * 10 that have also been identified by SEP as having malware, sorted by bytes.`
  },
  {
    useCase: `Network - PAN - high Internet traffic from hosts with malware - critical user`,
    domain: `Endpoint`,
    spl: ``,
    comments: `[CUSTOMER]Net IPs / users with connections where bytes sent > bytes received * 10 that have also been identified by SEP as having malware, sorted by bytes. Critical users.`
  },
  {
    useCase: `"Endpoint - anomalous new service - critical user. Should we change this to confirm to priority chart?"`,
    domain: `Endpoint`,
    spl: `| tstats allow_old_summaries=true sum(Web.bytes_out) as "bytes_out" from datamodel=Web where   nodename=Web "Web.bytes_out">0 AND ("Web.src_priority"="high" OR "Web.src_priority"="critical") by "Web.src","Web.dest"  | rename "Web.src" as "src","Web.dest" as "dest" | where 'bytes_out'>10485760`,
    comments: `Could indicate malware . Marginal at best. Better to use Cybereason.`
  },
  {
    useCase: `SEP - Hosts with high process count - critical user. Should we change this to confirm to priority chart?`,
    domain: `Endpoint`,
    spl: `index=ecat_process |stats count(process_path) by machine |sort -count(process_path)`,
    comments: ``
  },
  {
    useCase: `Disabled - Endpoint - SEP - Hosts with high process count WAS High Process Count -->`,
    domain: `Endpoint`,
    spl: ``,
    comments: `Unknown, need to understand what this identifies.`
  },
  {
    useCase: `SEP - prohibited process detected WAS Prohibited Process Detected"`,
    domain: `Endpoint`,
    spl: `|datamodel Network_Sessions VPN search | search [|inputlookup _identities.csv | search priority=high OR priority=critical | fields + identity | rename identity AS All_Sessions.user] | table All_Sessions.user _time src roles msg`,
    comments: `Instances of 'bad' processes that have attempted to run via SEP.`
  },
  {
    useCase: `SEP - host with excessive listening ports WAS Host With High Number Of Listening ports`,
    domain: `Endpoint`,
    spl: `| tstats allow_old_summaries=true count from datamodel=Intrusion_Detection by IDS_Attacks.signature | \`drop_dm_object_name("IDS_Attacks")\` | xswhere count from count_by_signature_1h in ids_attacks by signature is above medium`,
    comments: ``
  },
  {
    useCase: `[CUSTOMER]-AD - Logon to multiple non-servers - insider threat`,
    domain: `Access`,
    spl: `index=ad sourcetype="Snare:Security" EventCode=4769 ( Service_Name = "w*" OR Service_Name = "l*" OR Service_Name="t*" ) Service_Name!="WAC*" Service_Name!="WCR*" Service_Name!="WAL*" Service_Name!="WOD*" Service_Name!="*W410*" Service_Name!="LTV*" Service_Name!="LUZ*" Service_Name!="TNT*" Service_Name!="TOP*" Service_Name!="TWT*" user!="*$@-ad.net" NOT [|inputlookup _identities.csv | eval identity=identity."*" |  makemv delim="|" category | where category="shared" | rename identity as user | table user ] |stats dc(Service_Name) values(Service_Name) by user | rename dc(Service_Name) as "Distinct Endpoints" | where "Distinct Endpoints" > 5`,
    comments: `Find users logging on to multiple [CUSTOMER]-AD hosts over a given period of time, sorted by number of hosts.`
  },
  {
    useCase: `[CUSTOMER]-AD - Default account activity successful`,
    domain: `Access`,
    spl: `| tstats summariesonly=t count FROM datamodel=Authentication where nodename=Authentication.Failed_Default_Authentication (Authentication.app="win:remote") by Authentication.user Authentication.src Authentication.dest Authentication.action Authentication.app  | sort - count`,
    comments: `Show 'default' accounts that are being used - [CUSTOMER]-AD `
  },
  {
    useCase: `[CUSTOMER]-AD - Default account login failure`,
    domain: `Access`,
    spl: `| tstats summariesonly=t count FROM datamodel=Authentication where nodename=Authentication.Failed_Default_Authentication ( Authentication.app="win:remote") by Authentication.user Authentication.src Authentication.dest Authentication.action Authentication.app  | sort - count`,
    comments: `Identify when use of default accounts has failed for Windows environment.`
  },
  {
    useCase: `[CUSTOMER]-AD - Disabled account re-enabled - $ account`,
    domain: `Access`,
    spl: `| tstats summariesonly=t count FROM datamodel=Authentication where nodename=Authentication (Authentication.EventCode=4722) by Authentication.user Authentication.action Authentication.dest Authentication.dest_category Authentication.dest_priority Authentication.src`,
    comments: `Disabled $ account is enabled.`
  },
  {
    useCase: `[CUSTOMER]-AD - Excessive failed logons - 1 day WAS Brute Force Access Behavior Detected Over One Day`,
    domain: `Access`,
    spl: `| tstats allow_old_summaries=true values(Authentication.app) as app,count(eval('Authentication.action'=="failure")) as failure,count(eval('Authentication.action'=="success")) as success from datamodel=Authentication by Authentication.src | \`drop_dm_object_name("Authentication")\` | where success > 0 | xswhere failure from failures_by_src_count_1d in authentication is above high | \`settags("access")\``,
    comments: `Unknown, need to understand what this identifies.`
  },
  {
    useCase: `[CUSTOMER]-AD - Excessive failed local logons - high value system`,
    domain: `Access`,
    spl: ``,
    comments: `User / systems  with failed local logons to [CUSTOMER]-AD critical systems.`
  },
  {
    useCase: `[CUSTOMER]-AD - Excessive failed logons WAS Brute Force Access Behavior Detected`,
    domain: `Access`,
    spl: `index=ad sourcetype="Snare:Security" EventCode=4625 | regex User!="\\$$"  | stats count sparkline as trend values(Workstation_Name) as Workstations earliest(_time) as earliestTime latest(_time) as latestTime by User, src_ip | where count > 3 | eval earliestTime=strftime(earliestTime, "%Y-%m-%d %H:%M:%S") | eval latestTime=strftime(latestTime, "%Y-%m-%d %H:%M:%S") | sort - count`,
    comments: `High counts of failed user logons to [CUSTOMER]-AD, sorted by count of login attempts.`
  },
  {
    useCase: `[CUSTOMER]-AD - logon from geography previously not seen - privileged accounts`,
    domain: `Access`,
    spl: ``,
    comments: `Identify admin logons from geographies not previously seen.`
  },
  {
    useCase: `[CUSTOMER]-AD - Excessive failed logons - multiple accounts from same host`,
    domain: `Access`,
    spl: `\`authentication\` | tags outputfield=tag | stats values(tag) as tag,count(eval(action=="failure")) as failure,count(eval(action=="success")) as success by src | search failure>200 success>0 | \`settags("access")\``,
    comments: `[CUSTOMER]-AD hosts with a multiple failed logons from distinct accounts, sorted by failed logon attempts.`
  },
  {
    useCase: `[CUSTOMER]-AD - Excessive password changes`,
    domain: `Access`,
    spl: `index=ad sourcetype="Snare:Security" (EventCode=4723 OR EventCode=4724) | regex User!="\\$$" | stats count  dc(user) as UserCount values(user) as Users by src_user | where count > 1 | where UserCount > 5 | sort -UserCount`,
    comments: `[CUSTOMER]-AD admins who have changed >10 user passwords in <1 hour`
  },
  {
    useCase: `[CUSTOMER]-AD - local account created on multiple critical or high systems`,
    domain: `Access`,
    spl: `"|tstats count from datamodel=Authentication where nodename=Authentication (""Authentication.EventCode""=""4720"") by Authentication.dest
| join type=outer Authentication.dest [|inputlookup _assets.csv | search priority=high OR priority=critical | rename nt_host as Authentication.dest]
|fields Authentication.dest count"`,
    comments: ``
  },
  {
    useCase: `[CUSTOMER]-AD - logon attempt from disabled account`,
    domain: `Access`,
    spl: `|tstats summariesonly=t count from datamodel=Authentication where nodename=Authenticaiton.Failed_Authentication (Authentication.EventCode=4728) by Authentication.user Security_ID Authentication.app Authentication.dest`,
    comments: `Logon attempts to disabled [CUSTOMER]-AD accounts`
  },
  {
    useCase: `[CUSTOMER]-AD - logon attempt from disabled account - $ account`,
    domain: `Access`,
    spl: `|datamodel Authentication Failed_Authentication search | search Authentication.EventCode=4625 xc000006e___Sub_Status=0xC0000072 Authentication.user="$*" | table Authentication.user host Failure_Reason`,
    comments: `Logon attempts to disabled [CUSTOMER]-AD accounts - critical accounts`
  },
  {
    useCase: `[CUSTOMER]-AD - logon attempt from disabled account - critical account`,
    domain: `Access`,
    spl: `tag=privileged EventCode=4625 xc000006e___Sub_Status=0xC0000072 | table user host Failure_Reason`,
    comments: ``
  },
  {
    useCase: `[CUSTOMER]-AD - logon from/to AD host not seen before - privileged account`,
    domain: `Access`,
    spl: ``,
    comments: `Identify privileged account logons to/from [CUSTOMER]-AD systems that had not previously been seen.`
  },
  {
    useCase: `[CUSTOMER]-AD - Multiple interactive logons - privileged account`,
    domain: `Access`,
    spl: ``,
    comments: `[CUSTOMER]-AD privileged account interactive logons.`
  },
  {
    useCase: `[CUSTOMER]-AD - Multiple interactive logons - domain admin`,
    domain: `Access`,
    spl: `index=ad sourcetype="Snare:Security" EventCode=4624 User!="NT AUTHORITY\\ANONYMOUS LOGON" | regex User!="\\$$" | rex field=dest_nt_host "^(?<destHost>[^\\.]+)" | eval srcHost=upper(src_nt_host) | eval destHost=upper(destHost) | where srcHost != destHost | stats count sparkline as trend dc(srcHost) as HostCount values(srcHost) as Hosts earliest(_time) as earliestTime latest(_time) as latestTime by User | search [|inputlookup _identities | makemv delim="|" category | where category="administrator" | eval User="*".identity | table User] | eval earliestTime=strftime(earliestTime, "%Y-%m-%d %H:%M:%S") | eval latestTime=strftime(latestTime, "%Y-%m-%d %H:%M:%S") | sort - count`,
    comments: `[CUSTOMER]-AD adminstrator accounts interactive logons.`
  },
  {
    useCase: `[CUSTOMER]-AD - Mutliple Interactive logons - $ accounts`,
    domain: `Access`,
    spl: `index=ad sourcetype="Snare:Security" EventCode=4624 User!="NT AUTHORITY\\\\ANONYMOUS LOGON" | regex User!="\\$$" | rex field=dest_nt_host "^(?<destHost>[^\\.]+)" | eval srcHost=upper(src_nt_host) | eval destHost=upper(destHost) | where srcHost != destHost | stats count sparkline as trend dc(srcHost) as HostCount values(srcHost) as Hosts earliest(_time) as earliestTime latest(_time) as latestTime by User | search [|inputlookup _identities | makemv delim="|" category | where category="administrator" | eval User="*".identity | table User] | eval earliestTime=strftime(earliestTime, "%Y-%m-%d %H:%M:%S") | eval latestTime=strftime(latestTime, "%Y-%m-%d %H:%M:%S") | sort - count`,
    comments: `[CUSTOMER]-AD adminstrator accounts interactive logons.`
  },
  {
    useCase: `[CUSTOMER]-AD - Successful iInteractive logons - service accounts`,
    domain: `Access`,
    spl: `index=ad sourcetype="Snare:Security" (EventCode=4625 OR EventCode=4624) User!="NT AUTHORITY*" | search [|inputlookup administrative_identity_lookup | makemv delim="|" identity | eval user=identity | table user] | eval Workstation_Name=if(isnull(Workstation_Name),host,Workstation_Name) | stats count sparkline as trend sum(eval(action="success")) as success_count sum(eval(action="failure")) as failure_count values(Workstation_Name) as Workstations earliest(_time) as earliestTime latest(_time) as latestTime by User, src_ip | fillnull | eval earliestTime=strftime(earliestTime, "%Y-%m-%d %H:%M:%S") | eval latestTime=strftime(latestTime, "%Y-%m-%d %H:%M:%S") | sort - count`,
    comments: `[CUSTOMER]-AD systems / users with logons using 'administrative' identities, sorted by user count.`
  },
  {
    useCase: `[CUSTOMER]-AD - user added to Domain Admin group`,
    domain: `Access`,
    spl: `| tstats \`summariesonly\` count from datamodel=Authentication by _time,Authentication.app,Authentication.src,Authentication.user span=1s | \`drop_dm_object_name("Authentication")\` | eventstats dc(src) as src_count by app,user | search src_count>1  Authentication.EventCode=3210 OR Authentication.EventCode=5722`,
    comments: `Users are added to [CUSTOMER]-AD Domain Admins group.`
  },
  {
    useCase: `Unix/Linux - Default account activity failed`,
    domain: `Access`,
    spl: ``,
    comments: `Show 'default' accounts logon attemp failures - unix/linux`
  },
  {
    useCase: `Unix/Linux - Default account activity successful`,
    domain: `Access`,
    spl: `| tstats summariesonly=t count FROM datamodel=Authentication where nodename=Authentication.Privileged_Authentication (Authentication.EventCode=4728) by Authentication.user Authentication.src_user Authentication.user_category Authentication.user_priority Security_ID`,
    comments: `Show 'default' accounts that are being used - unix`
  },
  {
    useCase: `Unix/Linux - Excessive Failed Logins`,
    domain: `Access`,
    spl: `| tstats summariesonly=t count FROM datamodel=Authentication where nodename=Authentication.Failed_Default_Authentication (Authentication.app=sshd) by Authentication.user Authentication.src Authentication.dest Authentication.action Authentication.app | sort - count`,
    comments: `Failed logon attempts to unix / linux systems / accounts, sorted by count of username.`
  },
  {
    useCase: `[CUSTOMER]-AD - Succesful local logon to system - FinSig`,
    domain: `Access`,
    spl: `| inputlookup append=T listeningports_tracker | eval earliestQual=case(match("-24h@h", "^\\d"), tostring("-24h@h"),  match("-24h@h", "^([@\\+-]){1}"), relative_time(time(), "-24h@h"),  true(), time()) | eval latestQual=case(match("+0s", "^\\d"), tostring("+0s"),  match("+0s", "^([@\\+-]){1}"), relative_time(time(), "+0s"),  true(), time()) | where (firstTime>=earliestQual AND firstTime<=latestQual) | fields - earliestQual, latestQual | stats dc(dest) as "dest_count" by "transport","dest_port" | where 'dest_count'>10`,
    comments: `User / systems with succesful local logons to [CUSTOMER]-AD FinSig systems.`
  },
  {
    useCase: `[CUSTOMER]-AD - domain admin logon from/to host not seen before`,
    domain: `Access`,
    spl: ``,
    comments: `Identify admin logons to/from [CUSTOMER]-AD systems that had not previously been seen.`
  },
  {
    useCase: `Unix - Administrator logon from/to host not seen before`,
    domain: `Access`,
    spl: `| tstats summariesonly=t count FROM datamodel=Authentication where nodename=Authentication.Default_Authentication (Authentication.action=success Authentication.app=sshd) by Authentication.user Authentication.src Authentication.dest Authentication.action Authentication.app | sort - count`,
    comments: `Identify admin logons to/from Unix systems that had not previously been seen.`
  },
  {
    useCase: `Windows Failed Logins`,
    domain: `Access`,
    spl: `"| \`tstats\`
  values(Authentication.Sub_Status) as Sub_Status,
  values(Authentication.dest) as destination,
  values(Authentication.EventCode) as EventCode,
  values(Authentication.Failure_Code) as Failure_Code,
  values(Authentication.Error_Code) as Error_Code,
  dc(Authentication.user) as user_count,
  values(Authentication.Result_Code) as Result_Code,
  dc(Authentication.dest) as dest_count,
  values(Authentication.Service_Name) as Service_Name,
  values(Authentication.Logon_Type) as Logon_Type

count from datamodel=Authentication where
  nodename=Authentication.Failed_Authentication
  Authentication.user!=*$*
  Authentication.user!=""*@*""
  NOT(Authentication.src=::*)

by Authentication.src,Authentication.user

| stats count
  values(Authentication.dest) as destination,
  values(Authentication.EventCode) as EventCode,
  values(Authentication.Failure_Code) as Failure_Code,
  values(Authentication.Error_Code) as Error_Code,
  dc(Authentication.user) as user_count,
  values(Authentication.Result_Code) as Result_Code,
  values(Authentication.Sub_Status) as Sub_Status,
  dc(Authentication.dest) as dest_count
  values(Authentication.Service_Name) as Service_Name,
  values(Authentication.Logon_Type) as Logon_Type

by Authentication.src,Authentication.user | rename Authentication.* AS * | where 'count'>=10

| eval user=lower(user) | search user!=srv.ltc.dtviewer user!=srv.ltc.foglight user!=dsa.ltc.sndiegopharm user!=nxs7041 EventCode=*

| eval destination=mvjoin(destination,"" | "")
| eval EventCode=mvjoin(EventCode,"" | "")
| eval ErrorCode=upper(coalesce(Error_Code,Sub_Status,Failure_Code,Result_Code))

| lookup authcodes code AS ErrorCode OUTPUT priority, description AS code_description
| lookup authcodes code AS Logon_Type OUTPUT priority, description AS code_description
| eval
  priority=if(match(upper(Service_Name),""krbtgt""),""informational"",priority),
  code_description=if(match(Service_Name,""krbtgt""),""Passive endpoint authentication"",code_description)

| table src,user_count,user,dest_count,destination,EventCode,ErrorCode,count,code_description,priority"`,
    comments: `Tuned Failed Login search`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `index=wineventlog (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `index=wineventlog (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog* Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog* (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4768 action=failure user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4720 EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_nick`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Reason, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4768 user!=*$* action=failure | timechart span=1h count by user`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4720 EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" SourceName!="AD FS Auditing" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4768 user!=*$* | timechart span=1h count by user`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `index=wineventlog (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `index=wineventlog (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog* Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog* (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4768 action=failure user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4720 EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4768 action=failure user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=172.16.0.0/12  Source_Network_Address!="-" | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Reason, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") user!="*$"| table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4728 OR EventCode=4732 OR EventCode=4756| table _time, EventCode, user, user_group, member_id`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_nick`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename Caller_User_Name as ChangedBy| table _time, TargetUser, src_user, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4720 EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4768 user!=*$* | timechart span=1h count by user`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time (Failed auths)`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 NOT(user="*$*" OR user="-") | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time (Failed auths)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time (DC attempted to validate creds)`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype="WinEventLog:Security" EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time (DC attempted to validate creds)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time (Kerberos ticket requested)`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype="WinEventLog:Security" EventCode=4768 action=failure user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4768 Event Code Failures by Time (Kerberos ticket requested)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (Success auths from external IPs)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4624 Source_Network_Address="*.*.*.*" Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::*" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" Source_Network_Address!="64.202.64.0/20" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (Success auths from external IPs)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses (Failed auths)`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses (Failed auths)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures (Failed RDP)`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures (Failed RDP)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog* EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4768 user!=*$* | timechart span=1h count by user`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `index=wineventlog* sourcetype=*security* (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4720 EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4768 user!=*$* | timechart span=1h count by user`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (Geo-locations)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | dedup Source_Network_Address | iplocation Source_Network_Address | geostats count by src_ip globallimit=0`,
    comments: `Windows 4624 Events Generated from External IP Addresses (Geo-locations)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4768 action=failure user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Windows Authentication Items of Interest | EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit`,
    comments: `EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code by Time`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4625 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4776 Event Code by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4776 action=failure | timechart count by user limit=0`,
    comments: `Windows 4776 Event Code by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4768 Event Code Failures by Time`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4768 action=failure user!=*$* | timechart span=1h count by user limit=0`,
    comments: `Windows 4768 Event Code Failures by Time`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4624 Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!="-" Source_Network_Address!="fe80::bc14:7b36:22d2:9851" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status | dedup Source_Network_Address`,
    comments: `Windows 4624 Events Generated from External IP Addresses (No Duplicate Source_Network_Address)`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Events Generated from External IP Addresses`,
    domain: `Access`,
    spl: `index=* sourcetype="WinEventLog:Security" EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status`,
    comments: `Windows 4625 Events Generated from External IP Addresses`
  },
  {
    useCase: `Windows Authentication Items of Interest | Event Code 1102/517 | Windows Security Event Log Cleared`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=1102 OR EventCode=517`,
    comments: `Event Code 1102/517 | Windows Security Event Log Cleared`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows New Service Installation`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)`,
    comments: `Windows New Service Installation`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows 4625 Event Code | Remote Desktop Failures`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype=WinEventLog:Security Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status`,
    comments: `Windows 4625 Event Code | Remote Desktop Failures`
  },
  {
    useCase: `Windows Authentication Items of Interest | Windows Disabled Account Login Attempts`,
    domain: `Access`,
    spl: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason`,
    comments: `Windows Disabled Account Login Attempts`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Count`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse`,
    comments: `User Password Reset Count`
  },
  {
    useCase: `Windows Authentication Items of Interest | User Password Reset Events`,
    domain: `Access`,
    spl: `sourcetype="WinEventLog:Security" (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status`,
    comments: `User Password Reset Events`
  },
  {
    useCase: `Windows Authentication Items of Interest | Users Added to Domain Security Groups`,
    domain: `Access`,
    spl: `index=wineventlog EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group`,
    comments: `Users Added to Domain Security Groups`
  },
  {
    useCase: `Access - [CUSTOMER]-AD - User added to privileged group`,
    domain: `Identity | Asset`,
    spl: `User is added to a privileged group.`,
    comments: `|datamodel Network_Traffic All_Traffic search| search All_Traffic.app=smtp src_zone="Net" | stats count dc(All_Traffic.dest_ip) as dc_dst_ip dc(dst_location) as dc_dst_location  by All_Traffic.src_ip src_zone All_Traffic.action All_Traffic.user | sort -dc_dst_ip, -count`
  },
  {
    useCase: `PAN - High outbound traffic critical system`,
    domain: `Network`,
    spl: `index=pan_logs sourcetype="pan_traffic" dst_zone="Outside" ABLE_TO_TRANSFER_FILE="yes" PRONE_TO_MISUSE="yes" | where ((bytes_sent > 5000) AND (bytes_sent > (bytes_received *10))) | stats sum(bytes_sent) sparkline avg(RISK) by src_ip, dst_ip, dst_port, dst_location, app | sort -avg(RISK),-sum(bytes_sent)`,
    comments: `Critical systems with connections where bytes sent > bytes received * 10, sorted by bytes.`
  },
  {
    useCase: `DNS - rare DNS queries`,
    domain: `Network`,
    spl: `"|datamodel Network_Traffic  Blocked_Traffic search | search All_Traffic.dst_zone=""Internet"" All_Traffic.src_zone=""Net""
| stats count dc(All_Traffic.dest_ip) as dc_dst_ip dc(All_Traffic.dest_port) as dc_dst_port by All_Traffic.src_ip, All_Traffic.user | where count > 3000"`,
    comments: ``
  },
  {
    useCase: `DNS -  Endpoints with excessive DNS requests - critical systems`,
    domain: `Network`,
    spl: `| tstats allow_old_summaries=true dc(All_Traffic.src) as src_count,count from datamodel=Network_Traffic | localop | xswhere count from count_30m in network_traffic is extreme or src_count from src_count_30m in network_traffic is extreme | eval const_dedup_id="Network - Unusual Volume of Network Activity - Rule"`,
    comments: `Systems with high amount of DNS requests to [CUSTOMER]-AD DNS proxies by requesting system IP address - not username - removing some common DNS names, sorted by count of requests.`
  },
  {
    useCase: `DNS - Endpoints with excessive DNS requests - critical users`,
    domain: `Network`,
    spl: ``,
    comments: `Systems with high amount of DNS requests to [CUSTOMER]-AD DNS proxies by requesting system IP address - not username - removing some common DNS names, sorted by count of requests.`
  },
  {
    useCase: `DNS - Endpoints with excessive DNS requests WAS Excessive DNS Queries`,
    domain: `Network`,
    spl: `index=ad sourcetype=snare:dns questionname!="*ars*" AND questionname!="*arpa*" AND questionname!="*google*" AND questionname!="*akamai*" AND questionname!="*yahoo*" AND questionname!="*cloudfront*"  AND questionname!="*apple*" AND questionname!="*msft*" AND questionname!="*" AND questionname!="*effem*" AND questionname!="*symantec*" AND questionname!="*microsoft*" AND questionname!="*lync*" AND questionname!="*Citrix*" AND questionname!="*facebook*" AND questionname!="*Twitter*"   direction=Snd  src_ip!=1.60.105.75 AND src_ip!=1.20.21.101 AND src_ip!=1.60.150.76| eval qn1=replace(questionname, "\(\d+\)",".")  | eval qn2=replace(qn1, "^\.", "")  | stats  count by src_ip |where count > 2500 |sort -count`,
    comments: `Systems with high amount of DNS requests to [CUSTOMER]-AD DNS proxies by requesting system IP address - not username - removing some common DNS names, sorted by count of requests.`
  },
  {
    useCase: `DNS - excessive requests to FQDN`,
    domain: `Network`,
    spl: `| datamodel Threat_Intelligence Threat_Activity search | \`drop_dm_object_name("Threat_Activity")\` | dedup threat_match_field,threat_match_value | \`get_event_id\` | table _raw,event_id,source,src,dest,threat* | \`per_panel_filter("ppf_threat_activity","threat_match_field,threat_match_value")\` | \`makesv(src)\` | \`makesv(dest)\` | \`get_threat_attribution(threat_key)\` | rename source as orig_source,source_* as threat_source_*,description as threat_description | \`map_notable_fields\` | fields - *time | eval risk_object_type=case(threat_match_field="query" OR threat_match_field=="src" OR threat_match_field=="dest","system",threat_match_field=="src_user" OR threat_match_field=="user","user",1=1,"other") | eval risk_object=threat_match_value`,
    comments: `Identify whe [CUSTOMER]Net systems are making a very high amount (?) of requests to a specific FQDN.`
  },
  {
    useCase: `PAN - high network traffic on critical host WAS High Volume of Traffic from High or Critical Host Observed -->`,
    domain: `Network`,
    spl: ``,
    comments: `Unknown, need to understand what this identifies.`
  },
  {
    useCase: `Network activity - tunneling application usage from FinSig systems`,
    domain: `Network`,
    spl: ``,
    comments: `Identify FinSig systems with high usage of tunneling applications from inside network to Internet.`
  },
  {
    useCase: `VPN - logon from admin/ privileged account`,
    domain: `Network`,
    spl: `index=bt_vpn sourcetype="bt_vpn_logs" (msg="AUT24326*" OR msg="AUT24327*") | rex field=msg "^(?<AUT_code>AUT(24326|24327))" | search [|inputlookup _identities | makemv delim="|" category | where category="administrator" | eval user="*".identity | table user] | iplocation src | stats count sparkline sum(eval(AUT_code="AUT24326")) as success_count sum(eval(AUT_code="AUT24327")) as failure_count dc(src) as dc_src dc(Country) as dc_Country values(Country) as values_Country by user | fillnull | sort -count`,
    comments: `Identify MAW ([CUSTOMER]Anywhere remote access SSL VPN) successful logons using admin or privileged accounts.`
  },
  {
    useCase: `PAN -- Excessive email outbound connections`,
    domain: `Network`,
    spl: `index=pan_logs sourcetype="pan_traffic" dst_zone="Internet" src_zone="Net" app=SMTP | stats count sparkline dc(dst_ip) as dc_dst_ip dc(dst_location) as dc_dst_location by src_ip, src_zone, action, user | sort -dc_dst_ip, -count`,
    comments: `[CUSTOMER]Net systems attempting to make SMTP connections to the Internet, sorted by count of distinct destination IPs.`
  },
  {
    useCase: `PAN - Excessive email outbound connections - critical systems`,
    domain: `Network`,
    spl: `"| tstats allow_old_summaries=true sum(Web.bytes_out) as ""bytes_out"" from datamodel=Web where nodename=Web ""Web.bytes_out"">0 by ""Web.src"",""Web.dest"", | rename ""Web.src"" as ""src"",""Web.dest"" as ""dest""  | where 'bytes_out'>10485760
| join type=inner dest [|inputlookup _assets.csv | rename ip AS dest | fields + nt_host dest]
| join type=inner dest [| tstats allow_old_summaries=true values(Malware_Attacks.signature) as ""signature"" from datamodel=Malware where earliest=-24h latest=+0s nodename=Malware_Attacks.Allowed_Malware  by ""Malware_Attacks.dest"" | rename ""Malware_Attacks.dest"" as ""dest""]"`,
    comments: `[CUSTOMER]Net systems attempting to make SMTP connections to the Internet, sorted by count of distinct destination IPs.`
  },
  {
    useCase: `PAN - Excessive firewall deny events to Internet`,
    domain: `Network`,
    spl: `| tstats allow_old_summaries=true sum(Web.bytes_out) as "bytes_out" from datamodel=Web where nodename=Web "Web.bytes_out">0 by "Web.src","Web.dest", | rename "Web.src" as "src","Web.dest" as "dest"  | where 'bytes_out'>10485760`,
    comments: `Source IP addreses of systems with denied [CUSTOMER]Net -> Internet connections, by source IP and user, showing amount of destination IPs denied, sorted by distinct count of dest ports`
  },
  {
    useCase: `PAN - Excessive firewall deny events to Internet - critical system`,
    domain: `Network`,
    spl: `| join type=inner dest [|inputlookup _assets.csv | rename ip AS dest | fields + nt_host dest]`,
    comments: `Source IP addreses of systems with denied [CUSTOMER]Net -> Internet connections, by source IP and user, showing amount of destination IPs denied, sorted by distinct count of dest ports`
  },
  {
    useCase: `PAN - Excessive network activity WAS Unusual Volume of Network Activity`,
    domain: `Network`,
    spl: `| join type=inner dest [| tstats allow_old_summaries=true values(Malware_Attacks.signature) as "signature" from datamodel=Malware where earliest=-24h latest=+0s nodename=Malware_Attacks.Allowed_Malware ('Malware_Attacks.dest_priority'="high" OR 'Malware_Attacks.dest_priority'="critical") by "Malware_Attacks.dest" | rename "Malware_Attacks.dest" as "dest"]`,
    comments: `Unknown, need to understand what this identifies.`
  },
  {
    useCase: `PAN - Excessive requests to multiple web sites  - critical system`,
    domain: `Network`,
    spl: `"|datamodel Network_Traffic All_Traffic search| search All_Traffic.app=smtp src_zone=Net
|join type=inner All_Traffic.user [|inputlookup _identities.csv | search priority=high OR priority=critical | fields + identity | rename identity AS All_Traffic.user]
| stats count dc(All_Traffic.dest_ip) as dc_dst_ip dc(dst_location) as dc_dst_location  by All_Traffic.src_ip src_zone All_Traffic.action All_Traffic.user | sort -dc_dst_ip, -count"`,
    comments: `[CUSTOMER]Net IPs with connections to a high amount of Internet distinct destination IP addresses - critical host`
  },
  {
    useCase: `PAN - Excessive requests to multiple web sites - critical user`,
    domain: `Network`,
    spl: ``,
    comments: `[CUSTOMER]Net IPs with connections to a high amount of Internet distinct destination IP addresses - critical user`
  },
  {
    useCase: `PAN - Excessive web requests`,
    domain: `Network`,
    spl: `"| datamodel ""Intrusion_Detection"" ""IDS_Attacks"" search
| stats dc(IDS_Attacks.signature) as ""count"" by ""IDS_Attacks.src"" ""IDS_Attacks.dest""
| join type=outer IDS_Attacks.src [|inputlookup _assets.csv  | fields + ip | rename ip AS IDS_Attacks.src]
| rename ""IDS_Attacks.src"" as ""src"" ""IDS_Attacks.dest"" as ""dest""
| where count > 25"`,
    comments: `[CUSTOMER]Net IPs with a high amount of web requests`
  },
  {
    useCase: `PAN - Excessive web requests to multiple web sites`,
    domain: `Network`,
    spl: `index=pan_logs sourcetype="pan_traffic" dst_zone="Internet" src_zone="Net" action="Allow" (dst_port="80" OR dst_port="443") | stats count dc(dst_ip) as dc_dst_ip dc(dst_location) as dc_dst_location avg(RISK) as avg_risk by src_ip, user, src_zone | sort 50 -dc_dst_ip`,
    comments: `[CUSTOMER]Net IPs with connections to a high amount of Internet distinct destination IP addresses`
  },
  {
    useCase: `PAN - external port scan`,
    domain: `Network`,
    spl: `index=pan_logs sourcetype="pan_traffic" ( src_zone="Internet" OR src_zone="*Outside" ) | stats count sparkline sum(eval(action="allow")) as permits sum(eval(action="deny")) as denies mode(bytes_received) as mode_bytes_received dc(dst_ip) as dc_dst_ip dc(dst_port) as dc_dst_port values(protocol) as values_protocol min(dst_port) as min_port max(dst_port) as max_port by src_ip, src_location | fillnull | where dc_dst_port > 50 AND mode_bytes_received = 0 | eval port_range=min_port."-".max_port | sort -count | fields - max_port, min_port`,
    comments: `Internet IPs with deny events to multiple IP addresses. Sort by deny events.`
  },
  {
    useCase: `PAN - Host sending excessive email - critical system`,
    domain: `Network`,
    spl: ``,
    comments: ``
  },
  {
    useCase: `Network - PAN - Host sending excessive email - critical user`,
    domain: `Network`,
    spl: ``,
    comments: ``
  },
  {
    useCase: `PAN - Host sending excessive email WAS Host Sending Excessive Email`,
    domain: `Network`,
    spl: ``,
    comments: ``
  },
  {
    useCase: `PAN - internal system host or port scan`,
    domain: `Network`,
    spl: `index=pan_logs sourcetype="pan_traffic" src_zone!="Internet" dst_zone!="Internet" | stats count sparkline sum(eval(action="allow")) as permits sum(eval(action="deny")) as denies mode(bytes_received) as mode_bytes_received dc(dst_ip) as dc_dst_ip dc(dst_port) as dc_dst_port values(protocol) as values_protocol min(dst_port) as min_port max(dst_port) as max_port by src_ip | fillnull | where dc_dst_port > 50 AND mode_bytes_received = 0 | eval port_range=min_port."-".max_port | sort -count | fields - max_port, min_port`,
    comments: `List of internal IPs with high amounts of permits to various internal Ips and ports.`
  },
  {
    useCase: `PAN - internal system Internet host or port scan`,
    domain: `Network`,
    spl: `| tstats allow_old_summaries=true values(IDS_Attacks.tag) as "tag",dc(IDS_Attacks.signature) as "count" from datamodel=Intrusion_Detection where   nodename=IDS_Attacks  by "IDS_Attacks.src"  | rename "IDS_Attacks.src" as "src" | where 'count'>25 | eval tag=mvjoin(tag,"|") | rename "tag" as "orig_tag"`,
    comments: `List of internal IPs with high amounts of permits to various internal Ips and ports.`
  },
  {
    useCase: `PAN - Internet traffic detected - FinSig systems`,
    domain: `Network`,
    spl: ``,
    comments: `Identify FinSig systems with high usage of tunneling applications from inside network to Internet.`
  },
  {
    useCase: `PAN - malware / botnet traffic evidence - critical system`,
    domain: `Network`,
    spl: ``,
    comments: `Critical [CUSTOMER]Net systems + users that have connection to malware / botnet URL categories, sorted by count.`
  },
  {
    useCase: `PAN - malware / botnet traffic evidence - critical user`,
    domain: `Network`,
    spl: ``,
    comments: `Critical users that have connection to malware / botnet URL categories, sorted by count.`
  },
  {
    useCase: `PAN - malware / botnet traffic evidence WAS Botnet tracker`,
    domain: `Network`,
    spl: `index=pan_logs action=block-url ( category=Malware OR category=Botnet ) dst_zone="Internet" src_zone="Net" | stats count sparkline dc(dst_ip) as dc_dst_ip dc(dst_location) as dc_dst_location avg(RISK) as avg_risk by src_ip, dst_ip, user, host | sort -count`,
    comments: `Systems that have connection to malware / botnet URL categories, sorted by count.`
  },
  {
    useCase: `PAN - tunneling application usage`,
    domain: `Network`,
    spl: ``,
    comments: `Identify systems with high usage of tunneling applications.`
  },
  {
    useCase: `Squid - Excessive requests`,
    domain: `Network`,
    spl: `tag=vpn msg="AUT24326*" | iplocation src | stats count dc(src) as dc_src dc(Country) as dc_Country values(Country) as values_Country by user | sort -count | where dc_Country > 1 | fields - count dc_src`,
    comments: `[CUSTOMER]Net IPs with connections to a high amount of URLs.`
  },
  {
    useCase: `Squid - Excessive requests by critical endpoint`,
    domain: `Network`,
    spl: `| tstats \`summariesonly\` values(Authentication.app) as app, latest(Authentication.user_bunit) as user_bunit from datamodel=Authentication by Authentication.user,Authentication.src _time span=1s | \`drop_dm_object_name("Authentication")\` | eventstats dc(src) as src_count by user | search src_count>1  | sort 0 + _time| \`get_asset(src)\` | iplocation src | eval session_lat=if(isnull(src_lat), lat, src_lat) | eval session_lon=if(isnull(src_long), lon, src_long) | eval session_city=if(isnull(src_city), City, src_city)  | where isnotnull(session_lat) and isnotnull(session_lon) | sort 0 + _time  | streamstats current=t window=2 earliest(session_lat) as prev_lat, earliest(session_lon) as prev_lon, earliest(session_city) as prev_city, earliest(_time) as prev_time, earliest(src) as prev_src, latest(user_bunit) as user_bunit by user | where (src!=prev_src) | globedistance lat1=session_lat lon1=session_lon lat2=prev_lat lon2=prev_lon outfield="distance" unit="miles" | eval distance=round(distance,2) | eval time_diff=if((_time-prev_time)==0, 1, _time - prev_time) | eval speed = round(distance*3600/time_diff,2)| where speed>500`,
    comments: `[CUSTOMER]Net IPs with connections to a high amount of Internet distinct destination IP addresses - critical host`
  },
  {
    useCase: `Squid - Excessive requests to multiple web sites by critical user`,
    domain: `Network`,
    spl: ``,
    comments: `[CUSTOMER]Net IPs with connections to a high amount of Internet distinct destination IP addresses - critical user`
  },
  {
    useCase: `VPN - logon from unauthorized account`,
    domain: `Network`,
    spl: `| tstats \`summariesonly\` max(_time) as _time from datamodel=Application_State where nodename=All_Application_State.Processes by All_Application_State.dest,All_Application_State.process | \`drop_dm_object_name("All_Application_State")\` | eventstats max(_time) as lastReportTime by dest | where _time==lastReportTime | stats dc(process) as process_count by dest | search process_count>200`,
    comments: `Identify MAW ([CUSTOMER]Anywhere remote access SSL VPN) successful logons using $ accounts.`
  },
  {
    useCase: `VPN - logons from multiple countries`,
    domain: `Network`,
    spl: `index=bt_vpn sourcetype="bt_vpn_logs" msg="AUT24326*" | iplocation src| stats count sparkline dc(src) as dc_src dc(Country) as dc_Country values(Country) as values_Country by user | sort -count | where dc_src > 1`,
    comments: `Users logging into MAW from multiple countries within a certain period of time.`
  },
  {
    useCase: `VPN - simultaneous logons`,
    domain: `Network`,
    spl: ``,
    comments: `Users logging into MAW ([CUSTOMER]Anywhere remote access SSL VPN) that are already logged into the service.`
  },
  {
    useCase: `DNS - Excessive DNS Failures - critical user`,
    domain: `Network`,
    spl: ``,
    comments: `Excessive NXDOMAIN responses to host - critical user`
  },
  {
    useCase: `DNS - Excessive DNS Failures WAS Excessive DNS Failures`,
    domain: `Network`,
    spl: `|tstats summariesonly=t count from datamodel=Web where nodename=Web (Web.category="proxy-avoidance-and-anonymizers") by Web.src Web.user Web.app Web.url`,
    comments: `Excessive NXDOMAIN responses to host`
  },
  {
    useCase: `VPN - logon from suspicious country`,
    domain: `Network`,
    spl: `"|tstats summariesonly=t count from datamodel=Web where nodename=Web (Web.category=""proxy-avoidance-and-anonymizers"") by Web.src Web.user Web.app Web.url
|join type=inner Web.user [|inputlookup _identities | search priority=high OR priority=critical | fields + identity | rename identity AS Web.user]"`,
    comments: `Users logging into MAW that are not in a country in which [CUSTOMER] has an office.`
  },
  {
    useCase: `PAN - host traffic increase - critical system`,
    domain: `Network`,
    spl: `index=pan_logs sourcetype="pan_traffic" src_zone="Inside" earliest=-15m@m latest=@m | stats count as session_count by src_ip, app | append [search index=pan_logs sourcetype="pan_traffic" src_zone="Inside" earliest=-1455m@m latest=-1440m@m | stats count as last_session_count by src_ip, app ] | stats values(session_count) as session_count values(last_session_count) as last_session_count by src_ip, app | fillnull | where session_count > last_session_count | eval difference=session_count-last_session_count | search [|inputlookup _assets | makemv delim="|" category | where category="financially_significant" | rename ip as src_ip | table src_ip] | lookup _assets ip as src_ip OUTPUT nt_host as src_nt_host | sort - difference`,
    comments: ``
  },
  {
    useCase: `DNS - multiple queries to previously unseen FQDN`,
    domain: `Network`,
    spl: ``,
    comments: `DNS requests to internal [CUSTOMER]-AD DNS proxies that have not been seen previously.`
  },
  {
    useCase: `DNS - multiple queries to previously unseen FQDN from internal critical system`,
    domain: `Network`,
    spl: ``,
    comments: `DNS requests to internal [CUSTOMER]-AD DNS proxies that have not been seen previously from internal critical systems.`
  },
  {
    useCase: `Threat Intel - Threat activity detected`,
    domain: `Threat`,
    spl: ``,
    comments: `Detect threat activity.`
  },
  {
    useCase: `PAN - Vuln scan detection - events WAS Vulnerability Scanner Detected (by events)`,
    domain: `Threat`,
    spl: ``,
    comments: ``
  },
  {
    useCase: `PAN - Vuln scan detection - targets Vulnerability Scanner Detected (by targets)`,
    domain: `Threat`,
    spl: ``,
    comments: ``
  },
  {
    useCase: `PAN - SPAM host`,
    domain: `Threat`,
    spl: `| datamodel Application_State Processes search | \`drop_dm_object_name("All_Application_State")\` | \`drop_dm_object_name("Processes")\` | \`get_interesting_processes\` | search is_prohibited=true | \`get_event_id\` | \`map_notable_fields\` | fields + orig_event_id,orig_raw,dest,process,note`,
    comments: `[CUSTOMER]Net IPs of systems / users attempting to connect to Internet SPAM sites.`
  },
  {
    useCase: `PAN - SPAM host - critical user`,
    domain: `Threat`,
    spl: ``,
    comments: `[CUSTOMER]Net IPs of systems / users attempting to connect to Internet SPAM sites - critical user.`
  },
  {
    useCase: `PAN - anonymous proxy`,
    domain: `Threat`,
    spl: `| tstats allow_old_summaries=true count from datamodel=Network_Resolution where   nodename=DNS "DNS.reply_code"!="No Error" by "DNS.src" | rename "DNS.src" as "src" | where 'count'>100`,
    comments: `Systems attempting to connect to Internet anonymous proxies.`
  },
  {
    useCase: `PAN - anonymous proxy - critical user`,
    domain: `Threat`,
    spl: ``,
    comments: `Systems attempting to connect to Internet anonymous proxies - critical user`
  },
  {
    useCase: `PAN - Malware C2`,
    domain: `Threat`,
    spl: ``,
    comments: `Systems attempting to connect to C2.`
  },
  {
    useCase: `PAN - Malware C2 - critical user`,
    domain: `Threat`,
    spl: ``,
    comments: `Systems attempting to connect to C2 - critical user`
  },
  {
    useCase: `PAN - malware hosts`,
    domain: `Threat`,
    spl: ``,
    comments: `Systems attempting to connect to malware hosts.`
  },
  {
    useCase: `PAN - malware hosts - critical user`,
    domain: `Threat`,
    spl: ``,
    comments: `Systems attempting to connect to malware hosts - critical user`
  },
  {
    useCase: `PAN - phishing`,
    domain: `Threat`,
    spl: ``,
    comments: `[CUSTOMER]Net IPs of systems / users attempting to connect to Internet phishing sites.`
  },
  {
    useCase: `Tor Exit Nodes`,
    domain: `Threat`,
    spl: ``,
    comments: `Users hitting TOR nodes, TOR exit nodes hitting DMZ`
  },
  {
    useCase: `Outgoing Threat Hit`,
    domain: `Threat`,
    spl: ``,
    comments: `Outgoing threat object match`
  },
  {
    useCase: `Incoming Threat Hit`,
    domain: `Threat`,
    spl: ``,
    comments: `Incoming Threat Object Match`
  },
  {
    useCase: `Network - Suspicious SSL Activity`,
    domain: `Machine Learning`,
    spl: ``,
    comments: `Monitor for new/expired/self signed SSL certs in use, spikes in traffic or anomolous behavior`
  },
  {
    useCase: `Network - Low and Slow Attacks`,
    domain: `Machine Learning`,
    spl: ``,
    comments: `Detection using netflow/firewall data of a port/vuln scan over time by a host`
  },
  {
    useCase: `Network - Non-standard Port Usage`,
    domain: `Machine Learning`,
    spl: ``,
    comments: `Detection using protocol analysis tool such as Netwitness/Bro/Stream of non-standard port/protocol usage (SSL over high ports for example)`
  },
];

//////////////////////////////////////////

let logSrcsList = [
  { logSrc: 'Active Directory' },
  { logSrc: 'Office 365' },
  { logSrc: 'Firewall' },
  { logSrc: 'Network Device Logs' },
  { logSrc: 'Windows Command Line Logging' },
  { logSrc: 'Symantec' },
  { logSrc: 'Assets' },
  { logSrc: 'Wineventlog' }
];

let dropAndSeedLogSrcs = function() {
  return new Promise( (resolve, reject) => {
    db.LogSrc.remove({}).then( () => {
      function asyncCreateDoc(doc) {
        return new Promise(resolveAsync => {
          db.LogSrc.create(doc)
            .then(createdDoc => {
              // console.log('CREATED DOCUMENT: ' + createdDoc);
              resolveAsync();
            });
        });
      }
      let createInteractions = logSrcsList.map(asyncCreateDoc);
      let createResults = Promise.all(createInteractions);
      createResults.then( () => {
        // console.log('DONE WITH CREATING LOGSOURCES');
        resolve();
      }).catch(err => {
        console.log('WAS NOT ABLE TO CREATE ALL USECASES', err);
        reject();
      });
    }).catch(err => {
      console.log('COULD NOT REMOVE ALL LOG SOURCES.' + err + ' \n \n \n \n \n \n \n \n');
      reject();
    });
  });
};

let dropAndSeedUseCases = function() {
  return new Promise( (resolve, reject) => {
    db.UseCase.remove({})
      .then( () => {
        function asyncCreateDoc(doc) {
          return new Promise(resolveAsync => {
            db.UseCase.create(doc)
              .then(createdDoc => {
                // console.log('CREATED DOCUMENT: ' + createdDoc);
                resolveAsync();
              });
          });
        }
        let createInteractions = useCaseList.map(asyncCreateDoc);
        let createResults = Promise.all(createInteractions);
        createResults.then( () => {
          // console.log('DONE WITH CREATING USECASES');
          resolve();
        }).catch(err => {
          console.log('WAS NOT ABLE TO CREATE ALL USECASES', err);
          reject();
        });
      }).catch(err => {
        console.log('WAS NOT ABLE TO REMOVE ALL USECASES: ', err);
        reject();
      });
    });
};

// db.LogSrc.remove({}).then( () => {
//   console.log('REMOVED ALL LOG SRCS \n \n \n \n \n \n \n \n');
//   logSrcsList.forEach(logsrc => {
//     db.LogSrc.create(logsrc)
//       .then(createdDoc => {
//         console.log('CREATED ', logsrc);
//       })
//       .catch(err => {
//         console.log(err);
//       });
//   })



/////////////////////////////////////////////////



let dashboardsList = [
  // Rett 47-57
  {
    dashboardName: `Event and license use by host - Windows`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC - Event and license use by host Clone</label>
  <fieldset submitButton="true">
    <input type="time" token="field1">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
    <input type="dropdown" token="field2" searchWhenChanged="true">
      <label>Windows sourcetype - Click submit after changing</label>
      <choice value="*">all</choice>
      <default>*</default>
      <initialValue>*</initialValue>
      <fieldForLabel>sourcetype</fieldForLabel>
      <fieldForValue>sourcetype</fieldForValue>
      <search>
        <query>|tstats count where index=win* by  sourcetype</query>
        <earliest>-7d@h</earliest>
        <latest>now</latest>
      </search>
    </input>
    <input type="dropdown" token="field3" searchWhenChanged="true">
      <label>Host - Click submit after changing</label>
      <choice value="*">all</choice>
      <initialValue>*</initialValue>
      <fieldForLabel>host</fieldForLabel>
      <fieldForValue>host</fieldForValue>
      <search>
        <query>|tstats count where index=win* by  host</query>
        <earliest>-7d@h</earliest>
        <latest>now</latest>
      </search>
    </input>
  </fieldset>
  <row>
    <panel>
      <chart>
        <title>Windows event counts per host graph - uses time, host, and sourcetype picker</title>
        <search>
          <query>|tstats count where index=win* sourcetype="$field2$" host="$field3$" by host  _time sourcetype  span=30m
|timechart limit=30 span=30m useother=f sum(count) by host
|sort count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Windows event counts per host statistics table - uses time, host, and sourcetype picker</title>
        <search>
          <query>|tstats count where index=win* sourcetype="$field2$" host="$field3$" by host  _time sourcetype  span=30m
|timechart limit=30 span=30m useother=f sum(count) by host
|sort count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Windows event counts by sourcetype - uses time and host picker</title>
        <search>
          <query>|tstats count where index=win* host="$field3$" by host  _time sourcetype  span=10m
|timechart limit=30 span=30m useother=f sum(count) by sourcetype
|sort count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Windows license use per host in MB - Hardcoded 4 hour time range example</title>
        <search>
          <query>index=_internal source=*license_usage.log type=Usage idx=win*
| eval totalMB = b/1024/1024
| eval totalGB = totalMB /1024
| timechart limit=30 span=30m useother=f sum(totalMB) by h
|fields - VALUE</query>
          <earliest>-4h@m</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
</form>`,
    comments: `Multiple Clients`
  },
  {
    dashboardName: `Malware events with details (needs threat_type field added to datamodel)`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC - Mcafee events</label>
  <fieldset submitButton="true" autoRun="true">
    <input type="time" token="field1">
      <label></label>
      <default>
        <earliest>-60m@m</earliest>
        <latest>now</latest>
      </default>
    </input>
    <input type="radio" token="field2">
      <label>action</label>
      <choice value="*">All</choice>
      <default>*</default>
      <initialValue>*</initialValue>
      <fieldForLabel>action_count</fieldForLabel>
      <fieldForValue>action</fieldForValue>
      <search>
        <query>|tstats summariesonly=true allow_old_summaries=t count from datamodel=Malware.Malware_Attacks where Malware_Attacks.dest=* by Malware_Attacks.action
|\`drop_dm_object_name("Malware_Attacks")\`
|eval action_count=action. " - " .count
|table action_count,action,count
|sort action_count</query>
        <earliest>$field1.earliest$</earliest>
        <latest>$field1.latest$</latest>
      </search>
    </input>
    <input type="dropdown" token="field5">
      <label>Threat type</label>
      <choice value="*">All</choice>
      <fieldForLabel>threat_type_count</fieldForLabel>
      <fieldForValue>threat_type</fieldForValue>
      <search>
        <query>|tstats summariesonly=true allow_old_summaries=t count from datamodel=Malware.Malware_Attacks where Malware_Attacks.dest=* by Malware_Attacks.threat_type
|\`drop_dm_object_name("Malware_Attacks")\`
|eval threat_type=LOWER(threat_type)
|eval threat_type_count=threat_type. " - " .count
|sort threat_type_count</query>
        <earliest>$field1.earliest$</earliest>
        <latest>$field1.latest$</latest>
      </search>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="field3">
      <label>User (allows wildcards)</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="field4">
      <label>Destination (allows wildcards, previously dest_nt_host)</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="field6">
      <label>Signature (allows wildcards)</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="field7">
      <label>File name (allows wildcards)</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <search>
          <query>|tstats summariesonly=true allow_old_summaries=t values from datamodel=Malware.Malware_Attacks where Malware_Attacks.dest="$field4$" Malware_Attacks.user="$field3$" Malware_Attacks.threat_type="$field5$" Malware_Attacks.signature="$field6$" Malware_Attacks.file_name="$field7$" by _time,Malware_Attacks.user,Malware_Attacks.dest,Malware_Attacks.signature,Malware_Attacks.threat_type,  Malware_Attacks.action,Malware_Attacks.file_name span=1s
|\`drop_dm_object_name("Malware_Attacks")\`
|sort _time</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with Lear. Need malware datamodel populated`
  },
  {
    dashboardName: `Web traffic breakdown using tstats`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC - Websense PoC</label>
  <fieldset submitButton="true" autoRun="true">
    <input type="time" token="field1">
      <label></label>
      <default>
        <earliest>-60m@m</earliest>
        <latest>now</latest>
      </default>
    </input>
    <input type="radio" token="field6">
      <label>Action</label>
      <choice value="*">All</choice>
      <default>*</default>
      <initialValue>*</initialValue>
      <fieldForLabel>action</fieldForLabel>
      <fieldForValue>action</fieldForValue>
      <search>
        <query>|tstats summariesonly=true allow_old_summaries=t values from datamodel=Web.Web where Web.action=* by Web.action
|\`drop_dm_object_name("Web")\`
|dedup action
|sort action</query>
        <earliest>-60m@m</earliest>
        <latest>now</latest>
      </search>
    </input>
    <input type="text" token="field2">
      <label>Username</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="field4">
      <label>Fully qualified domain name (dest)</label>
      <default>*</default>
      <suffix>*</suffix>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="field3">
      <label>URL</label>
      <default>*</default>
      <prefix>*</prefix>
      <suffix>*</suffix>
      <initialValue>*</initialValue>
    </input>
    <input type="multiselect" token="field5">
      <label>User business unit</label>
      <choice value="*">All</choice>
      <default>*</default>
      <prefix>(</prefix>
      <suffix>)</suffix>
      <initialValue>*</initialValue>
      <valuePrefix>Web.user_bunit="</valuePrefix>
      <delimiter> OR </delimiter>
      <fieldForLabel>user_bunit</fieldForLabel>
      <fieldForValue>user_bunit</fieldForValue>
      <search>
        <query>|tstats summariesonly=true allow_old_summaries=t values from datamodel=Web.Web where Web.user_bunit=* by Web.user_bunit
|\`drop_dm_object_name("Web")\`
|dedup user_bunit
|sort user_bunit</query>
        <earliest>-7d@h</earliest>
        <latest>now</latest>
      </search>
      <valueSuffix>"</valueSuffix>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <search>
          <query>|tstats summariesonly=true allow_old_summaries=t values from datamodel=Web.Web where Web.user="$field2$" Web.url="$field3$" Web.dest="$field4$" Web.action="$field6$" $field5$ by _time,Web.user, Web.src, Web.dest,Web.url, Web.action, Web.user_bunit,Web.bytes,Web.http_method span=1s
|\`drop_dm_object_name("Web")\`</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">20</option>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with Lear. Need web datamodel populated`
  },
  {
    dashboardName: `Cisco ASA Firewall Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Cisco ASA Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-15m</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <title>Firewall Changes - Last 7 Days</title>
        <search>
          <query>|tstats summariesonly=t allow_old_summaries=true values from datamodel=Change_Analysis.All_Changes where nodename="*Network*" by _time,host,sourcetype,All_Changes.command,All_Changes.user,All_Changes.src,All_Changes.vendor_product,All_Changes.change_type span=1s |\`drop_dm_object_name("All_Changes")\` | sort _time</query>
          <earliest>-7d@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Cisco ASA - Event Severity Timechart</title>
        <search>
          <query>index=firewall sourcetype=cisco:asa | timechart count by description limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Cisco ASA - Log Level 1 (Alert) - Message ID Timechart</title>
        <search>
          <query>index=firewall sourcetype=cisco:asa log_level=1 | timechart count by message_id limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Cisco ASA - Log Level 2 (Critical) - Message ID Timechart</title>
        <search>
          <query>index=firewall sourcetype=cisco:asa log_level=2 | timechart count by message_id limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Cisco ASA - Log Level 3 (Error) - Message ID Timechart</title>
        <search>
          <query>index=firewall sourcetype=cisco:asa log_level=3 | timechart count by message_id limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Cisco ASA - Log Level 4 (Warning) - Message ID Timechart</title>
        <search>
          <query>index=firewall sourcetype=cisco:asa log_level=4 | timechart count by message_id limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Cisco ASA - Log Level 5  (Notification) - Message ID Timechart</title>
        <search>
          <query>index=firewall sourcetype=cisco:asa log_level=5 | timechart count by message_id limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Cisco ASA - Log Level 6 (Informational) - Message ID Timechart</title>
        <search>
          <query>index=firewall sourcetype=cisco:asa log_level=6 | timechart count by message_id limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Cisco ASA - Log Level 7 (Debugging) - Message ID Timechart</title>
        <search>
          <query>index=firewall sourcetype=cisco:asa log_level=7 | timechart count by message_id limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>
</form>`,
    comments: `Tested with DDPA. Does not use datamodels.`
  },
  {
    dashboardName: `Cisco VPN Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Cisco VPN Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <map>
        <title>Cisco ASA | Successful User VPN Location Activity by User</title>
        <search>
          <query>index=firewall message_id=722051 | iplocation src_ip | geostats count by user globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">all</option>
        <option name="mapping.choroplethLayer.colorBins">5</option>
        <option name="mapping.choroplethLayer.colorMode">auto</option>
        <option name="mapping.choroplethLayer.maximumColor">0xDB5800</option>
        <option name="mapping.choroplethLayer.minimumColor">0x2F25BA</option>
        <option name="mapping.choroplethLayer.neutralPoint">0</option>
        <option name="mapping.choroplethLayer.shapeOpacity">0.75</option>
        <option name="mapping.choroplethLayer.showBorder">1</option>
        <option name="mapping.data.maxClusters">100</option>
        <option name="mapping.map.center">(0,0)</option>
        <option name="mapping.map.panning">1</option>
        <option name="mapping.map.scrollZoom">0</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMaxSize">50</option>
        <option name="mapping.markerLayer.markerMinSize">10</option>
        <option name="mapping.markerLayer.markerOpacity">0.8</option>
        <option name="mapping.showTiles">1</option>
        <option name="mapping.tileLayer.maxZoom">7</option>
        <option name="mapping.tileLayer.minZoom">0</option>
        <option name="mapping.tileLayer.tileOpacity">1</option>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
    <panel>
      <table>
        <title>Cisco ASA | Successful VPN Activity Events</title>
        <search>
          <query>index=firewall message_id=722051 | iplocation src_ip | stats count by user, src_ip, assigned_ip, group, Country, Region | table count, user, src_ip, assigned_ip, group, Country, Region | sort - count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">15</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="rowNumbers">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <map>
        <title>Cisco ASA | Successful IPSec Tunnel Locations</title>
        <search>
          <query>index=firewall message_id=602303 | rex "between\s(?&lt;src_user&gt;[^\s]+)" | rename src_user as src_ip | rename user as ip | iplocation src_ip | geostats count by ip globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
    <panel>
      <table>
        <title>Cisco ASA | Top Successful IPSec Tunnel Connections</title>
        <search>
          <query>index=firewall message_id=602303 | rex "between\s(?&lt;src_user&gt;[^\s]+)" | stats count by src_user, user, host, message_id | table count, src_user, user, host, message_id | rename src_user as src_ip | rename user as ip | sort - count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">15</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="rowNumbers">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with BHI. Does not use datamodels.`
  },
  {
    dashboardName: `Volume Sourcetype Statistics Dashboard`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | DDPA Sourcetype Volume Statistics</label>
  <fieldset submitButton="false">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-3d@d</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <title>Expected Host Not Reporting - 30 Day</title>
        <search>
          <query>| \`host_eventcount(30,24)\` | \`ctime(lastTime)\` | \`ctime(firstTime)\` | fields + host,firstTime,lastTime,is_expected,dayDiff</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Firewall Logs by Sourcetype</title>
        <search>
          <query>| tstats count WHERE index=firewall by _time,sourcetype span=15m | timechart limit=0 span=15m sum(count) as event_count by sourcetype</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">column</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Firewall Logs by Host</title>
        <search>
          <query>| tstats count WHERE index=firewall by _time,host span=15m  | timechart limit=0 span=15m sum(count) as event_count by host</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">column</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Windows Logs by Sourcetype</title>
        <search>
          <query>| tstats count WHERE index= by _time,sourcetype span=15m | timechart limit=0 span=15m sum(count) as event_count by sourcetype</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">column</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Windows Logs by Host</title>
        <search>
          <query>| tstats count WHERE index= by _time,host span=15m | timechart limit=0 span=15m sum(count) as event_count by host</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Wireless Access Point Logs by Sourcetype</title>
        <search>
          <query>| tstats count WHERE index=network by _time,sourcetype span=15m | timechart limit=0 span=15m sum(count) as event_count by sourcetype</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.drilldown">none</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Wireless Access Point Logs by Host</title>
        <search>
          <query>| tstats count WHERE index=network by _time,host span=15m | timechart limit=0 span=15m sum(count) as event_count by host</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.drilldown">none</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Endpoint Logs by Sourcetype</title>
        <search>
          <query>| tstats count WHERE index=endpoint by _time,sourcetype span=15m | timechart limit=0 span=15m sum(count) as event_count by sourcetype</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.drilldown">none</option>
      </chart>
    </panel>
  </row>
</form>`,
    comments: `This is DDPA's version. Will vary in customers based on ingested sourcetypes`
  },
  {
    dashboardName: `Meraki Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Meraki Statistics</label>
  <fieldset submitButton="false">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <chart>
        <title>Number of Attacks by Access Point</title>
        <search>
          <query>index=network sourcetype=meraki "airmarshal_events" | rex "ssid\=\'(?&lt;ssid&gt;[a-zA-Z0-9\s]+)\'" | rex "\stype=(?&lt;attack_type&gt;[^\s]+)" | search attack_type=* | stats count by host</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Count of Attacks by Type</title>
        <search>
          <query>index=network sourcetype=meraki "airmarshal_events" | rex "ssid\=\'(?&lt;ssid&gt;[a-zA-Z0-9\s]+)\'" | rex "\stype=(?&lt;attack_type&gt;[^\s]+)" | search attack_type=* | stats count by attack_type</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>SSID's Seen</title>
        <search>
          <query>index=network sourcetype=meraki "airmarshal_events" | rex "ssid\=\'(?&lt;ssid&gt;[a-zA-Z0-9\s]+)\'" | rex "src\=\'(?&lt;src_mac_address&gt;[^']+)\'" | rex "\stype=(?&lt;attack_type&gt;[^\s]+)" | dedup ssid | table ssid</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Number of Unique MAC Addresses by AP</title>
        <search>
          <query>index=network sourcetype=meraki |  rex "src\=\'(?&lt;src_mac_address&gt;[^']+)\'" | timechart span=1hr dc(src_mac_address) AS num_hosts BY host limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Traffic Distribution by MAC Address</title>
        <search>
          <query>index=network sourcetype=meraki src_mac=* | timechart count by src_mac limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
</form>`,
    comments: `Tested with DDPA. Does not use datamodels.`
  },
  {
    dashboardName: `Symantec Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Symantec Statistics</label>
  <fieldset submitButton="false">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-30d@d</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Symantec | Hosts with Threats Found</title>
      <table>
        <search>
          <query>index=endpoint sourcetype="symantec:ep:risk:file" | table _time,index,Source,vendor_action,signature,Category_Set,Category_Type,dest,dest_ip,file_name,file_path | sort - _time</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">row</option>
        <format type="color" field="eventcount">
          <colorPalette type="minMidMax" maxColor="#D6563C" minColor="#FFFFFF"></colorPalette>
          <scale type="minMidMax"></scale>
        </format>
        <format type="color" field="Description">
          <colorPalette type="sharedList"></colorPalette>
          <scale type="sharedCategory"></scale>
        </format>
        <format type="color" field="vendor_action">
          <colorPalette type="sharedList"></colorPalette>
          <scale type="sharedCategory"></scale>
        </format>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Symantec EP - Discovered Infections</title>
      <table>
        <search>
          <query>index=endpoint sourcetype="symantec:ep:scan:file" Infected_Files!=0 |dedup dest |sort -Infected_Files|rename dest as "Computer Name"|rename dest_ip as "IP Address" | table  "Computer Name" "IP Address" Infected_Files, Total_Files,Omitted_Files</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">row</option>
      </table>
    </panel>
    <panel>
      <title>Symantec EP - Top 10 Intrusion Types</title>
      <chart>
        <search>
          <query>index=endpoint sourcetype="symantec:ep:security:file" | stats count as "Intrusion Count" by "category" |sort -"Intrusion Count"|head 10</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Symantec EP - Hosts with Blocked Processes in Last 24H</title>
      <chart>
        <search>
          <query>index=endpoint sourcetype="symantec:ep:behavior:file" Description="blocked" | timechart count by Host_Name limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.text">Count</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">line</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
        <option name="height">240</option>
      </chart>
    </panel>
    <panel>
      <title>Symantec EP - Devices Where "Autorun.inf" was Blocked</title>
      <table>
        <search>
          <query>index=endpoint sourcetype="symantec:ep:behavior:file" Description="blocked" | rex "Device\sID:\s(?&lt;device_id&gt;[^\s]+)" | stats count by dest device_id | sort - count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">20</option>
        <option name="drilldown">cell</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with DDPA. Does not use datamodels.`
  },
  {
    dashboardName: `Cisco Firewall FTP Monitoring`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Cisco Firewall FTP Monitoring Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <chart>
        <title>Cisco FTP Upload/Download Activity by User</title>
        <search>
          <query>index=firewall message_id=303002 | rex "user\s(?&lt;user&gt;[^\s]+)" | timechart count by user limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <map>
        <title>Inbound FTP Traffic by Source IP</title>
        <search>
          <query>index=firewall message_id=303002 src_ip!=172.16.0.0/12 | iplocation src_ip | geostats count by src_ip globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
    <panel>
      <map>
        <title>Inbound FTP Traffic by User</title>
        <search>
          <query>index=firewall message_id=303002 src_ip!=172.16.0.0/12 | rex "user\s(?&lt;user&gt;[^\s]+)" | iplocation src_ip | geostats count by user globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
  </row>
  <row>
    <panel>
      <map>
        <title>Outbound FTP Traffic by Destination IP</title>
        <search>
          <query>index=firewall message_id=303002 src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16 | iplocation dest_ip | geostats count by dest_ip globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
    <panel>
      <map>
        <title>Outbound FTP Traffic by User</title>
        <search>
          <query>index=firewall message_id=303002 src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16 | rex "user\s(?&lt;user&gt;[^\s]+)" | iplocation dest_ip | geostats count by user globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
  </row>
</form>`,
    comments: `Tested with Verscend. Does not use datamodels`
  },
  {
    dashboardName: `CrowdStrike Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | CrowdStrike Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <title>CrowdStrike Detection Events By Signature/Host</title>
        <search>
          <query>index=endpoint | stats count by signature, event.SeverityName, dest, event.MachineDomain, event.DetectName, file_name, event.SHA1String, event.SHA256String | table count, signature, event.SeverityName, file_name, dest, event.MachineDomain, event.DetectName, event.SHA1String, event.SHA256String| sort - count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">30</option>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Last 24 hours - Medium, High, Critical Detections</title>
        <search>
          <query>index=endpoint ("event.SeverityName"=Informational OR "event.SeverityName"=Low OR "event.SeverityName"=Medium OR "event.SeverityName"=High OR "event.SeverityName"=Critical)  | bin _time span=1h | eval time=strftime(_time,"%b %d, %I%p") | chart dc(_raw) as "# of detections" over time by "event.SeverityName"</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>CrowdStrike - Activity by Host Timechart</title>
        <search>
          <query>index=endpoint event.ComputerName=* | timechart count by event.ComputerName limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="height">306</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>CrowdStrike - Host Alerts by Severity</title>
        <search>
          <query>index=endpoint event.ComputerName=* | chart count over  event.SeverityName by event.ComputerName limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>CrowdStrike- Critical Threat Activity</title>
      <table>
        <search>
          <query>index=endpoint event.ComputerName=* event.SeverityName=Critical | table _time, event.ComputerName, event.DetectName , event.DetectDescription, event.FileName, event.MD5String, event.SeverityName | sort - _time</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">20</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>CrowdStrike - High Threat Activity</title>
      <table>
        <search>
          <query>index=endpoint event.ComputerName=* event.SeverityName=High | table _time, event.ComputerName, event.DetectName , event.DetectDescription, event.FileName, event.MD5String, event.SeverityName | sort - _time</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">20</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>CrowdStrike- Medium Threat Activity</title>
      <table>
        <search>
          <query>index=endpoint event.ComputerName=* event.SeverityName=Medium | table _time, event.ComputerName, event.DetectName , event.DetectDescription, event.FileName, event.MD5String, event.SeverityName | sort - _time</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">20</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>CrowdStrike - Low Threat Activity</title>
      <table>
        <search>
          <query>index=endpoint event.ComputerName=* event.SeverityName=Low | table _time, event.ComputerName, event.DetectName , event.DetectDescription, event.FileName, event.MD5String, event.SeverityName | sort -_time</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">20</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>CrowdStrike - Authentication / Access Logging</title>
        <search>
          <query>index=endpoint "event.ServiceName"="CrowdStrike Authentication" | iplocation event.UserIp | table _time, event.Success, event.UserId, event.UserIp, Country, Region, event.OperationName | sort - time</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">20</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with Verscend. Does not use datamodels`
  },
  // Jeff 58-69
  {
    dashboardName: `F5 Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | F5 Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>F5 BIG-IP APM - Access Policy Results</title>
      <chart>
        <search>
          <query>index=network sourcetype="f5:bigip:apm:syslog" ": Access policy result:" | stats count by access_policy_result</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">-45</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">false</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">connect</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>F5 BIG-IP APM - Active Session Count</title>
      <chart>
        <search>
          <query>index=network sourcetype="f5:bigip:apm:syslog" ((": New session from client IP") OR (": Session deleted due to")) | transaction session_id startswith=": New session from client IP" endswith=": Session deleted due to" keepevicted=true | search ": New session from client IP" | multikv noheader=true | rex field=_raw "(?&lt;new_time_raw&gt;^[A-Za-z]{3,10}\s+\d{1,2}\s+\d{1,2}:\d{1,2}:\d{1,2})" | eval _time= strptime(new_time_raw, "%b %d %X") | rex field=_raw "(?&lt;session_status&gt;(: New session from client IP)|(: Session deleted due to))" | eval count_session=case(session_status==": New session from client IP",1,session_status==": Session deleted due to",-1) | sort +_time | timechart span=2min sum(count_session) as count_sum | streamstats sum(count_sum) as "Active Session Count"| table _time,"Active Session Count"</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">false</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">line</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">zero</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <title>F5 BIG-IP APM - Throughput</title>
      <chart>
        <search>
          <query>index=network sourcetype="f5:bigip:apm:syslog" ": Session statistics -" | timechart span=2min sum(bytes_in) as IN, sum(bytes_out) AS OUT</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">-45</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">false</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">line</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">connect</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>F5 BIG-IP APM - Session Duration Top 10</title>
      <table>
        <search>
          <query>index=network sourcetype="f5:bigip:apm:syslog" ((": New session from client IP") OR (": Session deleted due to")) | transaction session_id startswith=": New session from client IP" endswith=": Session deleted due to" | concurrency duration=duration | join session_id [search sourcetype="f5:bigip:apm:syslog"] | sort -duration | Rename session_id AS "Session ID" | rename user AS Username | eval Duration=tostring(duration, "duration") | table "Session ID",Username,Duration | head 10</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="rowNumbers">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>F5 BIG-IP APM - Session Variable Top 10</title>
      <table>
        <search>
          <query>index=network sourcetype="f5:bigip:apm:syslog" session_var_name!="" | stats count by session_var_name| rename session_var_name AS "Session Variable Name" | rename count AS "Count" | sort -"Count" | head 10</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="rowNumbers">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with Verscend. Does not use datamodels`
  },
  {
    dashboardName: `Palo Alto Threats Detected`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Palo Alto Threats Detected</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <title>Palo Alto Threat - Threat Activity by Type</title>
        <search>
          <query>index=firewall sourcetype=pan:threat src_ip!=63.128.163.21 src_ip!=63.128.163.22 src_ip!=63.128.163.23 src_ip!=63.128.163.24 src_ip!=63.128.163.25 src_ip!=63.128.163.26 src_ip!=63.128.163.27 src_ip!=63.128.163.28 src_ip!=63.128.163.29 src_ip!=63.128.163.20 | stats count by threat_name, vendor_action  | table count, threat_name, vendor_action | sort - count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">20</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">row</option>
      </table>
    </panel>
    <panel>
      <chart>
        <title>Palo Alto Threat - WhiteHat Security Scanning</title>
        <search>
          <query>index=firewall sourcetype=pan:threat src_ip=63.128.163.20 OR src_ip=63.128.163.21 OR src_ip=63.128.163.22 OR src_ip=63.128.163.23 OR src_ip=63.128.163.24 OR src_ip=63.128.163.25 OR src_ip=63.128.163.26 OR src_ip=63.128.163.27 OR src_ip=63.128.163.28 OR src_ip=63.128.163.29 | timechart count by threat_name limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.drilldown">none</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Palo Alto Threat - Activity by Time</title>
        <search>
          <query>index=firewall sourcetype=pan:threat src_ip!=63.128.163.21 src_ip!=63.128.163.22 src_ip!=63.128.163.23 src_ip!=63.128.163.24 src_ip!=63.128.163.25 src_ip!=63.128.163.26 src_ip!=63.128.163.27 src_ip!=63.128.163.28 src_ip!=63.128.163.29  | timechart span=1hr count by threat_name limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">column</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
        <option name="height">339</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Palo Alto Threat - DNS Threats</title>
        <search>
          <query>index=firewall sourcetype=pan:threat app=dns | table _time, vendor_action, host, src_ip, dest_ip, threat_name, signature, host</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with Verscend. Does not use datamodels`
  },
  {
    dashboardName: `Windows Authentication Items of Interest`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Windows Authentication Items of Interest</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <title>Users Added to Domain Security Groups</title>
        <search>
          <query>index=* EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time, host, EventCode, Account_Name, user_group</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">true</option>
        <option name="rowNumbers">false</option>
        <option name="drilldown">cell</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">5</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>EventCode 4722, 4725, 4726, 4767 Activity (Account Enabled/Disabled/Deleted/Unlocked)</title>
        <search>
          <query>index=* EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4767 | table _time, host, EventCode, user, status, subject, src_user_identity, user_bunit</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">undefined</option>
        <option name="rowNumbers">undefined</option>
        <option name="drilldown">row</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Windows 4625 Event Code by Time</title>
        <search>
          <query>index=* sourcetype=*security* EventCode=4625 user!=*$* | timechart span=1h count by user limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">column</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Windows 4776 Event Code by Time</title>
        <search>
          <query>index=* sourcetype=*security* EventCode=4776 action=failure | timechart count by user limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Windows 4768 Event Code Failures by Time</title>
        <search>
          <query>index=* sourcetype=*security* EventCode=4768 user!=*$* | timechart span=1h count by user</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Windows 4625 Events Generated from External IP Addresses</title>
        <search>
          <query>index=* sourcetype=*security* EventCode=4625 user!=*$* Source_Network_Address!=10.0.0.0/8 Source_Network_Address!=172.16.0.0/12 Source_Network_Address!=192.168.0.0/16 Source_Network_Address!=127.0.0.1  Source_Network_Address!="-"| table _time, host, src, Source_Network_Address, Logon_Type, user, EventCode, Sub_Status</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">20</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="rowNumbers">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <event>
        <title>Event Code 1102/517 | Windows Security Event Log Cleared</title>
        <search>
          <query>index=* sourcetype=*security* EventCode=1102 OR EventCode=517</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="list.drilldown">full</option>
        <option name="list.wrap">1</option>
        <option name="maxLines">5</option>
        <option name="raw.drilldown">full</option>
        <option name="rowNumbers">0</option>
        <option name="table.drilldown">all</option>
        <option name="table.wrap">1</option>
        <option name="type">list</option>
        <fields>["host","source","sourcetype"]</fields>
      </event>
    </panel>
    <panel>
      <event>
        <title>Windows New Service Installation</title>
        <search>
          <query>index=* sourcetype=*security* (EventCode=4697 OR EventCode=601)</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </event>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Windows 4625 Event Code | Remote Desktop Failures</title>
        <search>
          <query>index=* sourcetype=*security* Logon_Type=10 EventCode=4625 | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, user, EventCode, Error_Code, Failure_Code, Result_Code, Sub_Status</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">undefined</option>
        <option name="rowNumbers">undefined</option>
        <option name="drilldown">row</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">10</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Windows Disabled Account Login Attempts</title>
        <search>
          <query>index=* sourcetype=*security* EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") | table _time, host, src, Source_Network_Address, Logon_Process, Logon_Type, src_user_identity, user, EventCode, Sub_Status, Failure_Reason</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">undefined</option>
        <option name="rowNumbers">undefined</option>
        <option name="drilldown">row</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>User Password Reset Count</title>
        <search>
          <query>index=* sourcetype=*security* (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | chart count by user | sort by count | reverse</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">undefined</option>
        <option name="rowNumbers">undefined</option>
        <option name="drilldown">row</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>User Password Reset Events</title>
        <search>
          <query>index=* sourcetype=*security* (EventCode=628 OR EventCode=627 OR EventCode=4723 OR EventCode=4724) | rename user AS TargetUser | rename src_user_identity AS ChangedBy | rename Caller_User_Name as ChangedBy| table _time, TargetUser, user_bunit, ChangedBy, EventCode, signature, host, status</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">true</option>
        <option name="rowNumbers">false</option>
        <option name="drilldown">cell</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">5</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with Verscend. Does not use datamodels`
  },
  {
    dashboardName: `Cisco Estreamer Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Cisco Estreamer Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Cisco Sourcefire - Activity by Destination IP</title>
      <chart>
        <search>
          <query>index=estreamer sourcetype=estreamer dest_ip=* | timechart count by dest_ip limit=100</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">line</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Cisco Sourcefire - Activity by Src</title>
      <chart>
        <search>
          <query>index=estreamer sourcetype=estreamer src_ip=* | timechart count by src_ip limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">line</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Cisco Sourcefire - Severity by Dest IP</title>
      <map>
        <search>
          <query>index=estreamer sourcetype=estreamer dest_ip=* | iplocation dest_ip | geostats count by dest_ip globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">all</option>
        <option name="mapping.data.maxClusters">100</option>
        <option name="mapping.map.center">(0,0)</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMaxSize">50</option>
        <option name="mapping.markerLayer.markerMinSize">10</option>
        <option name="mapping.markerLayer.markerOpacity">0.8</option>
        <option name="mapping.tileLayer.maxZoom">7</option>
        <option name="mapping.tileLayer.minZoom">0</option>
      </map>
    </panel>
    <panel>
      <title>Cisco Sourcefire - Severity by Src IP</title>
      <map>
        <search>
          <query>index=estreamer sourcetype=estreamer src_ip=* | iplocation src_ip | geostats count by src_ip</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">all</option>
        <option name="mapping.data.maxClusters">100</option>
        <option name="mapping.map.center">(0,0)</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMaxSize">50</option>
        <option name="mapping.markerLayer.markerMinSize">10</option>
        <option name="mapping.markerLayer.markerOpacity">0.8</option>
        <option name="mapping.tileLayer.maxZoom">7</option>
        <option name="mapping.tileLayer.minZoom">0</option>
      </map>
    </panel>
  </row>
  <row>
    <panel>
      <title>Cisco Sourcefire - Threat Events</title>
      <table>
        <search>
          <query>index=estreamer sourcetype=estreamer class_desc=* | table _time, blocked, class_desc, src_ip, dest_ip, src_port, dest_port, fw_policy, fw_rule, msg | sort - _time</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Cisco Sourcefire - Top Client App</title>
      <chart>
        <search>
          <query>index=estreamer sourcetype=estreamer client_app=* | top client_app</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <title>Cisco Sourcefire - Top Web App</title>
      <chart>
        <search>
          <query>index=estreamer sourcetype=estreamer  web_app=* | top web_app</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Cisco Sourcefire - Top File Hash</title>
      <table>
        <search>
          <query>index=estreamer sourcetype=estreamer sha256=* | top sha256, uri | table count, percent, sha256, uri</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">row</option>
        <option name="rowNumbers">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested wtih BHI. Does not use datamodels`
  },
  {
    dashboardName: `Nessus Vulnerability Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Nessus Vulnerability Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-7d@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Nessus - Hosts Scanned (Within time picker range)</title>
      <single>
        <search>
          <query>index=vuln sourcetype="tenable:sc:vuln" | stats distinct_count(dnsName)</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="colorBy">value</option>
        <option name="colorMode">none</option>
        <option name="numberPrecision">0</option>
        <option name="rangeColors">["0x65a637","0x6db7c6","0xf7bc38","0xf58f39","0xd93f3c"]</option>
        <option name="rangeValues">[0,30,70,100]</option>
        <option name="showSparkline">1</option>
        <option name="showTrendIndicator">1</option>
        <option name="trendColorInterpretation">standard</option>
        <option name="trendDisplayMode">absolute</option>
        <option name="unitPosition">after</option>
        <option name="useColors">0</option>
        <option name="useThousandSeparators">1</option>
        <option name="linkView">search</option>
        <option name="unit">Hosts with scan results reported</option>
      </single>
    </panel>
    <panel>
      <title>Nessus - Total CVE's Detected (Within time picker range)</title>
      <single>
        <search>
          <query>index=vuln sourcetype="tenable:sc:vuln" cve=* | mvexpand cve | stats distinct_count(cve)</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="colorBy">value</option>
        <option name="colorMode">none</option>
        <option name="numberPrecision">0</option>
        <option name="rangeColors">["0x65a637","0x6db7c6","0xf7bc38","0xf58f39","0xd93f3c"]</option>
        <option name="rangeValues">[0,30,70,100]</option>
        <option name="showSparkline">1</option>
        <option name="showTrendIndicator">1</option>
        <option name="trendColorInterpretation">standard</option>
        <option name="trendDisplayMode">absolute</option>
        <option name="unitPosition">after</option>
        <option name="useColors">0</option>
        <option name="useThousandSeparators">1</option>
        <option name="linkView">search</option>
        <option name="unit">Distinct CVE's Detected</option>
      </single>
    </panel>
    <panel>
      <title>Nessus - Average Threat Score (Within time picker range)</title>
      <single>
        <search>
          <query>index=vuln sourcetype="tenable:sc:vuln" baseScore=* | stats avg(baseScore) AS "AvgRiskScore" | eval AvgRiskScore=round(AvgRiskScore,2)</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="colorBy">value</option>
        <option name="colorMode">none</option>
        <option name="numberPrecision">0</option>
        <option name="rangeColors">["0x65a637","0x6db7c6","0xf7bc38","0xf58f39","0xd93f3c"]</option>
        <option name="rangeValues">[0,30,70,100]</option>
        <option name="showSparkline">1</option>
        <option name="showTrendIndicator">1</option>
        <option name="trendColorInterpretation">standard</option>
        <option name="trendDisplayMode">absolute</option>
        <option name="unitPosition">before</option>
        <option name="useColors">0</option>
        <option name="useThousandSeparators">1</option>
        <option name="linkView">search</option>
        <option name="unit">Average Threat Score:</option>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <title>Nessus - Severity Count over Time (Last 7 Days)</title>
      <chart>
        <search>
          <query>index=vuln sourcetype="tenable:sc:vuln"  severity=* | timechart span=1h useother=false count by severity</query>
          <earliest>-7d@d</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">area</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <title>Nessus - Vulnerability Severity (Last 7 Days)</title>
      <chart>
        <search>
          <query>index=vuln sourcetype="tenable:sc:vuln"  | chart count(signature) by severity</query>
          <earliest>-7d@d</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Nessus - Hosts with Critical Vulnerabilities</title>
        <search>
          <query>index=vuln severity="critical" | chart count by dest</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Nessus - Critical Signatures by Severity</title>
      <table>
        <search>
          <query>index=vuln severity=critical | stats values(signature) as signature by severity | eval severity_level = case(severity=="critical",4,severity=="high",3,severity=="medium",2,severity=="low",1, severity=="informational",0) | sort  -severity_level | fields severity signature</query>
          <earliest>-7d@d</earliest>
          <latest>now</latest>
        </search>
        <drilldown>
          <!-- update drilldown if the click occurs in multivalued field (add that field to search constraint) -->
          <link field="signature">/app/search/search?q=sourcetype%3Dnessus%20signature="$click.value2$"%20starttimeu=$earliest$%20endtimeu=$latest$</link>
        </drilldown>
      </table>
    </panel>
    <panel>
      <table>
        <title>Nessus - High Signatures by Severity</title>
        <search>
          <query>index=vuln severity =high | stats values(signature) as signature by severity | eval severity_level = case(severity=="critical",4,severity=="high",3,severity=="medium",2,severity=="low",1, severity=="informational",0) | sort  -severity_level | fields severity signature</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Tenable Security Center - Cumulative Scan Results (Within Time Picker Range)</title>
      <table>
        <search>
          <query>index=vuln sourcetype="tenable:sc:vuln" | join max=0 [search sourcetype="tenable:sc:vuln" | dedup scan_result_info.id | sort -_time | dedup scan_result_info.name | table scan_result_info.id, scan_result_info.name] | search pluginID=* |rename scan_result_info.id AS ScanID |rename pluginID AS PluginID ,pluginName AS PluginName, family.name AS Family, severity AS Severity, ip AS IP, dnsName AS DNS, macAddress AS MACAddress, repository.name AS Repository |table PluginID, PluginName, Family, Severity, IP, DNS, MACAddress, Repository, ScanID | sort Severity</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">20</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with BHI. Does not use datamodels.`
  },
  {
    dashboardName: `Sophos Web Endpoint Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Sophos Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <event>
        <title>Sophos | Endpoint Alert Activity</title>
        <search>
          <query>index=endpoint BHI000596 type="Event::Endpoint::Threat*"</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </event>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Sophos Application Control | Blocked Applications by Host</title>
        <search>
          <query>index=endpoint type="Event::Endpoint::Application::Blocked" | rex "blocked\:\s(?&lt;software&gt;[a-zA-Z0-9\s\(\)\.\/]+)" | chart count over software by dhost limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Sophos Application Control | Blocked Applications Over Time</title>
        <search>
          <query>index=endpoint type="Event::Endpoint::Application::Blocked" | rex "blocked\:\s(?&lt;software&gt;[a-zA-Z0-9\s\(\)\.\/]+)" | timechart count by software limit=0 usenull=f</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Top Applications Blocked on Endpoints</title>
        <search>
          <query>index=endpoint type="Event::Endpoint::Application::Blocked" | rex "blocked\:\s(?&lt;software&gt;[a-zA-Z0-9\s\(\)\.\/]+)" | top software limit=10 | table software, count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Sophos Web Control | Blocked Traffic By Host Over Category</title>
        <search>
          <query>index=endpoint type="Event::Endpoint::WebControlViolation" | rex "category\s\'(?&lt;category&gt;[^\']+)" | chart count over category by dhost limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Sophos Web Control | Blocked Traffic by Category Over Time</title>
        <search>
          <query>index=endpoint type="Event::Endpoint::WebControlViolation" | rex "category\s\'(?&lt;category&gt;[^\']+)" | timechart count by category limit=0 usenull=f</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Sophos Web Control | Users Bypassing Category Blocks</title>
        <search>
          <query>index=endpoint type="Event::Endpoint::WebControlViolation" name="User bypass*" | rex "to\s\'(?&lt;url&gt;[^\']+)" | transaction suser | table suser, dhost, endpoint_type, severity, url</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with BHI. Does not use datamodels.`
  },
  {
    dashboardName: `ZScaler Web Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | ZScaler Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <chart>
        <title>ZScaler - Blocked Activity by URL Class (Security)</title>
        <search>
          <query>index=zscaler sourcetype=zscalerweblogs action=Blocked urlclass=*Security* | timechart count by urlclass limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>ZScaler - Blocked Activity by URL Class (Non-Security)</title>
        <search>
          <query>index=zscaler sourcetype=zscalerweblogs action=Blocked urlclass=* urlclass!="*Security*" | timechart count by urlclass limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>ZScaler - Blocked "Advanced Security Risk" Traffic by Signature</title>
        <search>
          <query>index=zscaler sourcetype=zscalerweblogs action=Blocked urlclass="*Security*" urlclass="Advanced Security Risk" | timechart count by signature limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>ZScaler - Blocked "Security Risk" Traffic</title>
        <search>
          <query>index=zscaler sourcetype=zscalerweblogs action=Blocked urlclass="*Security*" urlclass="Security Risk" | timechart count by category</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>ZScaler - Blocked Traffic by Department</title>
        <search>
          <query>index=zscaler sourcetype=zscalerweblogs action=Blocked user_bunit=* | timechart count by user_bunit limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="height">915</option>
      </chart>
    </panel>
  </row>
</form>`,
    comments: `Tested with BHI. Does not use datamodels.`
  },
  {
    dashboardName: `Cerberus FTP Host Monitoring`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Cerberus FTP Host Monitoring</label>
  <fieldset submitButton="false">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <chart>
        <title>Cerberus FTP Host | Account Login Timechart</title>
        <search>
          <query>index=web sourcetype=cerberus "Native user" NOT "Could not authenticate Native user"  | rex "^[^'\n]*'(?P&lt;user&gt;\w+)" | timechart count by user limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <map>
        <title>Cerberus FTP Host | Successful Login Locations</title>
        <search>
          <query>index=web sourcetype=cerberus | rex "^[^\[\n]*\[(?P&lt;session_id&gt;\d+)" | transaction session_id | search "Native user" "authenticated" | rex "from\s(?&lt;src_ip&gt;[^\s]+)" | rex "Native\suser\s(?&lt;src_user&gt;[^\s]+)" | iplocation src_ip | geostats count by user globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">all</option>
        <option name="mapping.choroplethLayer.colorBins">5</option>
        <option name="mapping.choroplethLayer.colorMode">auto</option>
        <option name="mapping.choroplethLayer.maximumColor">0xDB5800</option>
        <option name="mapping.choroplethLayer.minimumColor">0x2F25BA</option>
        <option name="mapping.choroplethLayer.neutralPoint">0</option>
        <option name="mapping.choroplethLayer.shapeOpacity">0.75</option>
        <option name="mapping.choroplethLayer.showBorder">1</option>
        <option name="mapping.data.maxClusters">100</option>
        <option name="mapping.map.center">(0,0)</option>
        <option name="mapping.map.panning">1</option>
        <option name="mapping.map.scrollZoom">0</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMaxSize">50</option>
        <option name="mapping.markerLayer.markerMinSize">10</option>
        <option name="mapping.markerLayer.markerOpacity">0.8</option>
        <option name="mapping.showTiles">1</option>
        <option name="mapping.tileLayer.maxZoom">7</option>
        <option name="mapping.tileLayer.minZoom">0</option>
        <option name="mapping.tileLayer.tileOpacity">1</option>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
    <panel>
      <map>
        <title>Cerberus FTP Host | Rejected/Blocked IP Addresses</title>
        <search>
          <query>index=web sourcetype=cerberus "connection request rejected" OR "has been automatically blocked" | rex "^[^'\n]*'(?P&lt;src_ip&gt;[^']+)" | iplocation src_ip | geostats count by src_ip globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
        <option name="mapping.choroplethLayer.colorBins">5</option>
        <option name="mapping.choroplethLayer.colorMode">auto</option>
        <option name="mapping.choroplethLayer.maximumColor">0xDB5800</option>
        <option name="mapping.choroplethLayer.minimumColor">0x2F25BA</option>
        <option name="mapping.choroplethLayer.neutralPoint">0</option>
        <option name="mapping.choroplethLayer.shapeOpacity">0.75</option>
        <option name="mapping.choroplethLayer.showBorder">1</option>
        <option name="mapping.data.maxClusters">100</option>
        <option name="mapping.map.center">(0,0)</option>
        <option name="mapping.map.panning">true</option>
        <option name="mapping.map.scrollZoom">false</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMaxSize">50</option>
        <option name="mapping.markerLayer.markerMinSize">10</option>
        <option name="mapping.markerLayer.markerOpacity">0.8</option>
        <option name="mapping.showTiles">1</option>
        <option name="mapping.tileLayer.maxZoom">7</option>
        <option name="mapping.tileLayer.minZoom">0</option>
        <option name="mapping.tileLayer.tileOpacity">1</option>
        <option name="drilldown">all</option>
      </map>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Cerberus FTP Host | Inbound Network Traffic by Service (Checkpoint Firewall)</title>
        <search>
          <query>index=network xlatedst=192.168.20.200 | chart count by service</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Cerberus FTP Host | Outbound Network Traffic by Service (Checkpoint Firewall)</title>
        <search>
          <query>index=network src=192.168.20.200 | chart count by service</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Cerberus FTP Host | Inbound Network Traffic by Source IP (Checkpoint Firewall)</title>
        <search>
          <query>index=network xlatedst=192.168.20.200 OR xlatedst=ftp.tharperobbins.com_Cerberus_192.168.20.200 | timechart count by src_ip limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">column</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
        <option name="height">360</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Cerberus FTP Host | Outbound Network Traffic by Destination IP (Checkpoint Firewall)</title>
        <search>
          <query>index=network (src_ip=ftp.tharperobbins.com_Cerberus_192.168.20.200 OR src_ip=192.168.20.200) NOT 10.157.3.45 | timechart count by dest_ip limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Cerberus FTP Host | Top 10 SSH Software Used</title>
        <search>
          <query>index=web sourcetype=cerberus "Client Identification:" | rex "^(?:[^:\n]*:){5}\s+(?P&lt;auth_method&gt;[^ ]+)" | top limit=10 auth_method</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="wrap">true</option>
        <option name="rowNumbers">false</option>
        <option name="drilldown">cell</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">10</option>
      </table>
    </panel>
    <panel>
      <chart>
        <title>Cerberus FTP Host | Windows Security Activity Timechart by EventCode</title>
        <search>
          <query>index= sourcetype=":Security" host=VMCBRUS-A NOT VMNETC-S$ | timechart count by subject limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">column</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="height">249</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Top 10 Users Seen Failing Authentication</title>
        <search>
          <query>index=web sourcetype=cerberus | search "Could not authenticate Native user"  | chart count by user | sort by count | reverse | rename user as User, count as Attempts | head 10</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with E2E. Does not use datamodels`
  },
  {
    dashboardName: `Checkpoint Threat Activity Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Checkpoint Threat Activity Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <title>Threat Types</title>
        <search>
          <query>index=network sourcetype=opsec:smartdefense Attack_Info=* | table _time, src, dest , action, Attack_Info | dedup Attack_Info</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="rowNumbers">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
    <panel>
      <title>Check Point Firewall - Bytes Received in Last 24H</title>
      <chart>
        <search>
          <query>sourcetype=opsec | timechart sum(bytes_in) as "Bytes in" span=1h</query>
          <earliest>-1d</earliest>
          <latest></latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.text">Bytes in</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">line</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">zero</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Threat Types by Time</title>
        <search>
          <query>index=network sourcetype=opsec:smartdefense Attack_Info=* | timechart span=1hr count by Attack_Info limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Clients Connecting to Checkpoint Sinkhole IP (Potentially Infected) - 7 Days</title>
        <search>
          <query>index=network 62.0.58.94 | chart count by src_machine_name</query>
          <earliest>-7d@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Checkpoint IPS Threat Emulation Files</title>
        <search>
          <query>index=network sourcetype=opsec:threat_emulation src!=169.130.15.145 src!=104.207.193.55 dst!=104.207.193.55 dst!=169.130.15.145 verdict!=Benign verdict!=Error | table _time, te_action, src, src_machine_name, src_user_name, dst, service, signature, malware_action, file_name, file_hash, resource</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">undefined</option>
        <option name="rowNumbers">undefined</option>
        <option name="drilldown">row</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Checkpoint IPS Anti-bot Malicious Events</title>
        <search>
          <query>index=network sourcetype=opsec:anti_malware te_action!=ctl  reason!="Check Point Online Web Service failure. See sk74040 for more information." | table _time, te_action, src, dst, service, orig, malware_family, malware_action, name, rule_name, resource</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">row</option>
      </table>
    </panel>
    <panel>
      <chart>
        <title>Checkpoint Anti-bot/Anti-Virus Web Services Check Errors</title>
        <search>
          <query>index=network reason="Check Point Online Web Service failure. See sk74040 for more information." | timechart count by orig</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Checkpoint IPS Anti-Virus Events (Excludes Barracuda &amp; Domain Controller DNS Events)</title>
        <search>
          <query>index=network sourcetype=opsec:anti_virus te_action!=ctl (src!=dc1-s src!=Minerva-A src!=Hestia3-A_10.130.0.5 src!=Hestia-S src!=Cronus2-S src!=Cronus-A src!=Barracuda-S) (dst!=169.130.15.145 dst!=104.207.193.55) | table _time, te_action, src, src_machine_name, src_user_name, dst, service, file_name, file_md5, name, malware_action, malware_family, resource, Destination_DNS_Hostname, orig, rule_name</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">undefined</option>
        <option name="rowNumbers">undefined</option>
        <option name="drilldown">row</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with E2E. Does not use datamodels`
  },
  {
    dashboardName: `Checkpoint VPN Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Checkpoint VPN Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <map>
        <title>Checkpoint VPN Login Locations</title>
        <search>
          <query>index=network client_name="Check Point Mobile" OR client_name="Endpoint Security VPN" | iplocation src_ip | geostats count by src_ip globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
        <option name="mapping.choroplethLayer.colorBins">5</option>
        <option name="mapping.choroplethLayer.colorMode">auto</option>
        <option name="mapping.choroplethLayer.maximumColor">0xDB5800</option>
        <option name="mapping.choroplethLayer.minimumColor">0x2F25BA</option>
        <option name="mapping.choroplethLayer.neutralPoint">0</option>
        <option name="mapping.choroplethLayer.shapeOpacity">0.75</option>
        <option name="mapping.choroplethLayer.showBorder">1</option>
        <option name="mapping.data.maxClusters">100</option>
        <option name="mapping.map.center">(0,0)</option>
        <option name="mapping.map.panning">true</option>
        <option name="mapping.map.scrollZoom">false</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMaxSize">50</option>
        <option name="mapping.markerLayer.markerMinSize">10</option>
        <option name="mapping.markerLayer.markerOpacity">0.8</option>
        <option name="mapping.showTiles">1</option>
        <option name="mapping.tileLayer.maxZoom">7</option>
        <option name="mapping.tileLayer.minZoom">0</option>
        <option name="mapping.tileLayer.tileOpacity">1</option>
        <option name="drilldown">all</option>
      </map>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Checkpoint VPN Login Events</title>
        <search>
          <query>index=network client_name="Check Point Mobile" OR client_name="Endpoint Security VPN" | iplocation src_ip | dedup src_ip, user_dn | table _time, user_dn, client_name, Hostname, src_ip, Region, Country, host_ip, office_mode_ip, os_name, os_version, os_edition, status, reason | sort - _time</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">true</option>
        <option name="rowNumbers">false</option>
        <option name="drilldown">cell</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">30</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with E2E. Does not use datamodels`
  },
  {
    dashboardName: `Cylance Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Cylance Statistics</label>
  <fieldset submitButton="false">
    <input type="time" token="field1">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Cylance - Threat Landscape</title>
      <single>
        <search>
          <query>index=protect eventtype=cylance_index sourcetype=syslog_protect EventName="threat_found" | chart count as total</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">all</option>
        <option name="refresh.display">none</option>
        <option name="underLabel">Threat(s) Allowed / Alerted</option>
      </single>
      <single>
        <search>
          <query>index=protect eventtype=cylance_index sourcetype=syslog_protect EventName=threat_quarantined | chart count as total</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">all</option>
        <option name="refresh.display">none</option>
        <option name="underLabel">Threat(s) Quarantined</option>
      </single>
      <single>
        <search>
          <query>index=protect eventtype=cylance_index sourcetype=syslog_protect EventName=threat_cleared | chart count as total</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">all</option>
        <option name="refresh.display">none</option>
        <option name="underLabel">Threat(s) Cleared</option>
      </single>
    </panel>
    <panel>
      <title>Cylance - Device Connection Status - Last 24 Hours</title>
      <single>
        <search>
          <query>index=protect eventtype=cylance_index sourcetype=device | stats latest("Is Online") as Status by "Device Name" | search Status=True | stats count</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">all</option>
        <option name="underLabel">Devices Online</option>
      </single>
      <single>
        <search>
          <query>index=protect eventtype=cylance_index sourcetype=device | stats latest("Is Online") as Status by "Device Name" | search Status=False | stats count</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">all</option>
        <option name="underLabel">Devices Offline</option>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Cylance Event Activity Timechart</title>
        <search>
          <query>index=protect eventtype=cylance_index sourcetype=syslog_protect  | timechart span=1hr count by EventName limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="height">396</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Cylance - Successful Login Events</title>
        <search>
          <query>index=protect eventtype=cylance_index sourcetype=syslog_protect EventName=LoginSuccess | rex "Source\sIP:\s(?&lt;src_ip&gt;[^,]+)" | rex "User:\s(?&lt;user&gt;[^,]+)" | rex "Event\sName:\s(?&lt;msg&gt;[^,]+)" | table _time, src_ip, user, msg | sort - _time</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="rowNumbers">true</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Cylance - Quarantine File Deletion Events</title>
        <search>
          <query>index=protect eventtype=cylance_index sourcetype=syslog_protect EventName="DeleteAllQuarantinedFiles" | rex "Device:\s(?&lt;device&gt;[^,]+)" | rex "User:\s(?&lt;user&gt;[^,]+)" | rex "Event\sName:\s(?&lt;msg&gt;[^,]+)" | table _time, device, user, msg | sort - _time</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Cylance Agent Count</title>
        <search>
          <query>index=protect eventtype=protect_inventory "Agent Version"=* | dedup "Device Name", "Agent Version" | chart count by "Agent Version" | sort by count | reverse</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.showPercent">true</option>
        <option name="height">255</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Cylance Agent Count</title>
        <search>
          <query>index=protect eventtype=protect_inventory "Agent Version"=* | dedup "Device Name", "Agent Version" | stats count by "Agent Version" | sort - count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="rowNumbers">true</option>
        <option name="totalsRow">true</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Cylance Operating System Count</title>
        <search>
          <query>index=protect eventtype=protect_inventory | dedup "Device Name" | stats count by "OS Version" | sort - count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Cylance - Systems With Suspected Exploit Attempt Events</title>
        <search>
          <query>index=protect eventtype="cylance_index" EventType="ExploitAttempt" | rex "Device\sName:\s(?&lt;device&gt;[^,]+)" | rex "IP\sAddress:\s\((?&lt;src_ip&gt;[^)]+)" | rex "Process\sName:\s(?&lt;process_name&gt;[^,]+)" | rex "User\sName:\s(?&lt;user_name&gt;[^,]+)" | rex "Violation\sType:\s(?&lt;violation_name&gt;[^,]+)" | rex "Event\sType:\s(?&lt;msg&gt;[^,]+)" | stats count by device, violation_name, process_name | table count, device, violation_name, process_name | sort - count</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with E2E. Does not use datamodels`
  },
  // Jeremy 70+
  {
    dashboardName: `Proofpoint Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | ProofPoint Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <chart>
        <title>AV Module Detections By Malware Family</title>
        <search>
          <query>index=mail mod=av rule=notcleaned | timechart count by name limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Top 10 IP's Sending Quarantined Mail</title>
        <search>
          <query>index=mail | transaction s | search action=quarantine ip!=127.0.0.1 | top ip limit=10</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Top Quarantined Email Subjects</title>
        <search>
          <query>index=mail | transaction s | search action=quarantine | top subject limit=100</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
    <panel>
      <table>
        <title>Top Recipients of Quarantined Mail</title>
        <search>
          <query>index=mail | transaction s | search action=quarantine | top rcpt limit=10</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Quarantined Mail Items by Filter Module</title>
        <search>
          <query>index=mail action=quarantine | chart count by module</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Quarantined Mail Items by Threat Vector</title>
        <search>
          <query>index=mail action=quarantine| top limit=20 folder</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">20</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with FPI. Does not use datamodels`
  },
  {
    dashboardName: `SQL Injection Statistics (Length Analysis)`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | SQL Injection Statistics Dashboard based on query field length</label>
  <searchTemplate>\`sqlinjection_stats($sourcetype_field$, $my_field$)\`|eval uri_query_field=$my_field$|eval clientip_field=clientip</searchTemplate>
  <fieldset>
    <input type="text" token="sourcetype_field">
      <label>Enter Sourcetype to check against</label>
    </input>
    <input type="text" token="my_field">
      <label>Enter URL Query Field</label>
    </input>
    <input type="time"></input>
  </fieldset>
  <row>
    <panel>
      <chart>
        <title>Top Outliers</title>
        <search base="global">
          <query>top uri_query_field</query>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.legend.placement">none</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Count of Outliers over Time</title>
        <search base="global">
          <query>timechart count by uri_query_field</query>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.legend.placement">none</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <map>
        <title>Map of client IP locations for injections</title>
        <search base="global">
          <query>rename clientip_field as ip|iplocation ip|geostats count by ip</query>
        </search>
        <option name="mapping.data.maxClusters">500</option>
        <option name="mapping.markerLayer.markerMaxSize">20</option>
        <option name="mapping.seriesColors">[0x0060DD]</option>
        <option name="mapping.map.zoom">2</option>
      </map>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Possible Injections</title>
        <search base="global">
          <query>table clientip_field uri_query_field</query>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Top Outliers</title>
        <search>
          <query>index=web sourcetype=access_combined
| eval len=len(path)
| eventstats avg(len) as avg stdev(len) as stdev
| where len&gt;(2.5*stdev+avg)
| top len</query>
          <earliest>$earliest$</earliest>
          <latest>$latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.drilldown">none</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Count of Outliers Over Time</title>
        <search>
          <query>index=web sourcetype=access_combined
| eval len=len(path)
| eventstats avg(len) as avg stdev(len) as stdev
| where len&gt;(2.5*stdev+avg)
| timechart count by len</query>
          <earliest>$earliest$</earliest>
          <latest>$latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.drilldown">none</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <map>
        <title>Map of Client IP Locations for Injections</title>
        <search>
          <query>index=web sourcetype=access_combined
| eval len=len(path)
| eventstats avg(len) as avg stdev(len) as stdev
| where len&gt;(2.5*stdev+avg)
| rename src_ip as ip
| iplocation ip
| geostats count by ip</query>
          <earliest>$earliest$</earliest>
          <latest>$latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Possible Injections</title>
        <search>
          <query>index=web sourcetype=access_combined
| eval len=len(path)
| eventstats avg(len) as avg stdev(len) as stdev
| where len&gt;(2.5*stdev+avg)
| table src_ip len</query>
          <earliest>$earliest$</earliest>
          <latest>$latest$</latest>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with FPI. Does not use datamodels`
  },
  {
    dashboardName: `SQL Injection Statistics (Pattern Analysis)`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | SQL Injection Patterns</label>
  <searchTemplate>\`sqlinjection_pattern($sourcetype_field$, $my_field$)\`|eval uri_query_field=$my_field$|eval clientip_field=clientip</searchTemplate>
  <fieldset>
    <input type="dropdown" token="sourcetype_field" searchWhenChanged="true">
      <label>Sourcetype</label>
      <choice value="iis">IIS</choice>
      <choice value="access_combined">APACHE</choice>
      <search>
        <query/>
        <earliest>-15m</earliest>
        <latest>now</latest>
      </search>
    </input>
    <input type="dropdown" token="my_field" searchWhenChanged="true">
      <label>Enter URL Query Field</label>
      <choice value="path">Apache</choice>
    </input>
    <input type="time" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Top Injection</title>
      <chart>
        <search>
          <query>index=web sourcetype=$sourcetype_field$
| rex field=$my_field$ "(?&lt;injection&gt;select.*?from|union.*?select|\\'$|delete.*?from|update.*?set|alter.*?table|([\\%27|\\'](%20)*=(%20)*[\\%27|\\'])|\\w*[%27|\\']or)"
| search injection=*
| top injection</query>
          <earliest>$earliest$</earliest>
          <latest>$latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.drilldown">none</option>
        <option name="height">277</option>
      </chart>
    </panel>
    <panel>
      <title>Patterns Over Time</title>
      <chart>
        <search>
          <query>index=web sourcetype=$sourcetype_field$
| rex field=$my_field$ "(?&lt;injection&gt;select.*?from|union.*?select|\\'$|delete.*?from|update.*?set|alter.*?table|([\\%27|\\'](%20)*=(%20)*[\\%27|\\'])|\\w*[%27|\\']or)"
| search injection=*
| timechart count by injection</query>
          <earliest>$earliest$</earliest>
          <latest>$latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.drilldown">none</option>
        <option name="height">340</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Map of client IP locations for injections</title>
      <map>
        <search>
          <query>index=web sourcetype=$sourcetype_field$
| rex field=$my_field$ "(?&lt;injection&gt;select.*?from|union.*?select|\\'$|delete.*?from|update.*?set|alter.*?table|([\\%27|\\'](%20)*=(%20)*[\\%27|\\'])|\\w*[%27|\\']or)"
| search injection=*
| rename src_ip as ip
| iplocation ip
| geostats count by ip</query>
          <earliest>$earliest$</earliest>
          <latest>$latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
  </row>
  <row>
    <panel>
      <title>List of Patterns</title>
      <table>
        <search>
          <query>index=web sourcetype=$sourcetype_field$
| rex field=$my_field$ "(?&lt;injection&gt;select.*?from|union.*?select|\\'$|delete.*?from|update.*?set|alter.*?table|([\\%27|\\'](%20)*=(%20)*[\\%27|\\'])|\\w*[%27|\\']or)"
| search injection=*
| table src_ip injection path</query>
          <earliest>$earliest$</earliest>
          <latest>$latest$</latest>
        </search>
        <option name="drilldown">cell</option>
      </table>
    </panel>
  </row>
</form>`,
    comments: `Tested with FPI. Does not use datamodels`
  },
  {
    dashboardName: `Juniper VPN Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Juniper VPN Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <map>
        <title>Juniper VPN - Succesful Login Locations</title>
        <search>
          <query>index=network sourcetype=juniper* (action=success) | dedup src_user | iplocation src_ip | geostats count by src_ip globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
        <option name="mapping.choroplethLayer.colorBins">5</option>
        <option name="mapping.choroplethLayer.colorMode">auto</option>
        <option name="mapping.choroplethLayer.maximumColor">0xDB5800</option>
        <option name="mapping.choroplethLayer.minimumColor">0x2F25BA</option>
        <option name="mapping.choroplethLayer.neutralPoint">0</option>
        <option name="mapping.choroplethLayer.shapeOpacity">0.75</option>
        <option name="mapping.choroplethLayer.showBorder">1</option>
        <option name="mapping.data.maxClusters">100</option>
        <option name="mapping.map.center">(0,0)</option>
        <option name="mapping.map.panning">true</option>
        <option name="mapping.map.scrollZoom">false</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMaxSize">50</option>
        <option name="mapping.markerLayer.markerMinSize">10</option>
        <option name="mapping.markerLayer.markerOpacity">0.8</option>
        <option name="mapping.showTiles">1</option>
        <option name="mapping.tileLayer.maxZoom">7</option>
        <option name="mapping.tileLayer.minZoom">0</option>
        <option name="mapping.tileLayer.tileOpacity">1</option>
        <option name="drilldown">all</option>
      </map>
    </panel>
    <panel>
      <map>
        <title>Juniper VPN - Failed Login Locations</title>
        <search>
          <query>index=network sourcetype=juniper* (action=failure) | dedup src_user | iplocation src_ip | geostats count by src_ip globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
        <option name="mapping.choroplethLayer.colorBins">5</option>
        <option name="mapping.choroplethLayer.colorMode">auto</option>
        <option name="mapping.choroplethLayer.maximumColor">0xDB5800</option>
        <option name="mapping.choroplethLayer.minimumColor">0x2F25BA</option>
        <option name="mapping.choroplethLayer.neutralPoint">0</option>
        <option name="mapping.choroplethLayer.shapeOpacity">0.75</option>
        <option name="mapping.choroplethLayer.showBorder">1</option>
        <option name="mapping.data.maxClusters">100</option>
        <option name="mapping.map.center">(0,0)</option>
        <option name="mapping.map.panning">true</option>
        <option name="mapping.map.scrollZoom">false</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMaxSize">50</option>
        <option name="mapping.markerLayer.markerMinSize">10</option>
        <option name="mapping.markerLayer.markerOpacity">0.8</option>
        <option name="mapping.showTiles">1</option>
        <option name="mapping.tileLayer.maxZoom">7</option>
        <option name="mapping.tileLayer.minZoom">0</option>
        <option name="mapping.tileLayer.tileOpacity">1</option>
        <option name="drilldown">all</option>
      </map>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Juniper VPN - Non-Business Hour Login | Weekdays (7PM - 5AM)</title>
        <search>
          <query>index=network sourcetype=juniper* action=success | eval hour = tonumber(strftime(_time,"%H")) | eval dow = tonumber(strftime(_time,"%w")) | where (dow!=0 AND dow!=6) AND (hour&lt;=5 OR hour&gt;=19) | timechart count by user limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Juniper VPN - Non-Business Hour Login | Weekends</title>
        <search>
          <query>index=network sourcetype=juniper* action=success | eval hour = tonumber(strftime(_time,"%H")) | eval dow = tonumber(strftime(_time,"%w")) |  where (dow=0 OR dow=6) | timechart count by user limit=0</query>
          <earliest>-7d@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Juniper VPN - Login Failures by Users Over Time</title>
        <search>
          <query>index=network sourcetype=juniper* action=failure | timechart count by user limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Juniper VPN - Top 10 Login Failure IP Addresses</title>
        <search>
          <query>sourcetype="juniper:sslvpn" action=failure | stats count by src_ip | rename src_ip as "Source IP Address" count as "Failure Count" | sort -"Failure Count" | head 10</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">undefined</option>
        <option name="rowNumbers">undefined</option>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Junipter VPN - Successful Login Device Hostnames by IP Address/Domain</title>
        <search>
          <query>index=network sourcetype=juniper* dest_nt_host=* | rex "^[^\\(\\n]*\\((?P&lt;domain&gt;[^\\)]+)" | iplocation src_ip | transaction dest_nt_host | table dest_nt_host, user, domain, src_ip, dest_ip, Region, Country | sort domain</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">50</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="rowNumbers">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Juniper VPN - Successful Login Event Location Details</title>
        <search>
          <query>index=network sourcetype=juniper* (action=success) | iplocation src_ip | transaction Country | transaction Country | table Country, Region, user, src_ip | sort Country</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">true</option>
        <option name="rowNumbers">false</option>
        <option name="drilldown">cell</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>
</form>`,
    comments:`Tested with FPI. Does not use datamodels`
  },
  {
    dashboardName:`Imperva WAF Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Imperva WAF Statistics</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <map>
        <title>Imperva WAF - Blocked Threat Activity by Location</title>
        <search>
          <query>index=network sourcetype=imperva* NOT "Agent status changed" vendor_action=Block | iplocation src | geostats count by Description globallimit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
      </map>
    </panel>
    <panel>
      <table>
        <title>Top 10 Foreign IP's Generating Unblocked Signature Activity</title>
        <search>
          <query>index=network sourcetype=imperva* sourcetype!="imperva:waf:firewall:cef" sourcetype!="imperva:waf:system:cef" vendor_action!=block NOT 10.16.2.155 src!=10.0.0.0/8 | iplocation src | search Country!="United States" | stats count by src, Country | table count, src, Country | sort - count | head 10</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Imperva WAF - Blocked Threat Activity Monitored</title>
        <search>
          <query>index=network sourcetype=imperva* NOT "Agent status changed" vendor_action=Block | timechart count by signature limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="height">412</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Imperva WAF - Blocked Threat Activity by ServerGroup</title>
        <search>
          <query>index=network sourcetype=imperva* NOT "Agent status changed" vendor_action=Block | timechart count by ServerGroup limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Imperva WAF - Blocked Threat Activity by ServiceName (Timechart)</title>
        <search>
          <query>index=network sourcetype=imperva* NOT "Agent status changed" vendor_action=Block | timechart count by ServiceName limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <event>
        <title>Imperva WAF - System Login Activity</title>
        <search>
          <query>index=network sourcetype=imperva* "User logged in"</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </event>
    </panel>
    <panel>
      <event>
        <title>Imperva WAF - System Logout Activity</title>
        <search>
          <query>index=network sourcetype=imperva* "logged out"</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </event>
    </panel>
  </row>
  <row>
    <panel>
      <event>
        <title>Imperva WAF - Failed System Login Activity</title>
        <search>
          <query>index=network sourcetype=imperva* tag=error "Login failed for user"</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
      </event>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Imperva DB Agents Starting Timechart by Agent Host</title>
        <search>
          <query>index=network sourcetype=imperva* "Agent status changed" started | rex "Agent\\s\\"(?&lt;agent_name&gt;[a-zA-Z0-9\\-]+)\\"" | rex "IP\\s(?&lt;agent_host&gt;[^\\ ]+)" | timechart count by agent_name limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="height">557</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Imperva WAF - Gateway Throughput Activity</title>
        <search>
          <query>index=network sourcetype=imperva* sourcetype="imperva:waf:system:cef" "Gateway throughput" | rex "gateway\\s(?&lt;imp_gateway&gt;[^\\s]+)" | rex "is\\s(?&lt;speed&gt;[^\\s]+)" | timechart span=1h values(speed) by imp_gateway limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="height">556</option>
      </chart>
    </panel>
  </row>
</form>`,
    comments:`Tested with FPI. Does not use datamodels`
  },
  {
    dashboardName: `TrendMicro Endpoint / Symantec DLP Statistics`,
    domain: `DOMAIN`,
    dashboardXML: `<form>
  <label>vSOC | Endpoint Solution Activity</label>
  <fieldset submitButton="true">
    <input type="time" token="field1" searchWhenChanged="true">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <table>
        <title>Trend Micro - Infection Activity</title>
        <search>
          <query>sourcetype=:Application:trendmicro TaskCategory=System Computer=* | table _time, Result, Computer, Domain, file_name, file_path, host, signature</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">15</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Trend Micro - Events Over Location by Activity</title>
        <search>
          <query>sourcetype=:Application:trendmicro TaskCategory=System Computer=* | chart count over Domain by Computer limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Trend Micro - Events Over Location by Action</title>
        <search>
          <query>sourcetype=WinEventLog:Application:trendmicro TaskCategory=System Computer=* | chart count over Domain by signature limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Symantec DLP - Timechart of Activity by Location</title>
        <search>
          <query>index=dlp NOT Test NOT Testing NOT "Vontu System Event" NOT financialpartners.service-now.com NOT central.financialpartners.com NOT mdm.financialpartners.com
  | timechart count by policy limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Symantec DLP - Events Over Location by Activity</title>
        <search>
          <query>index=dlp NOT Test NOT Testing NOT "Vontu System Event" NOT financialpartners.service-now.com NOT central.financialpartners.com NOT mdm.financialpartners.com | chart count over rules by policy limit=0</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Symantec DLP - Activities by Action</title>
      <chart>
        <search>
          <query>index=dlp sourcetype="symantec:dlp:syslog" action=*| timechart span=5m count(action) by action</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY.text">Action count</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">line</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <title>Symantec DLP - Top 10 Incident Senders</title>
      <table>
        <search>
          <query>index=dlp sourcetype="symantec:dlp:syslog" | top limit=10 showperc=false sender, Computer_Name</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="wrap">true</option>
        <option name="rowNumbers">true</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="count">10</option>
      </table>
    </panel>
    <panel>
      <title>Symantec DLP - Severity Distribution in Last 24H</title>
      <chart>
        <search>
          <query>index=dlp sourcetype="symantec:dlp:syslog" | chart Count by severity | rename severity as Severity</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>
        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>
        <option name="charting.axisTitleX.visibility">visible</option>
        <option name="charting.axisTitleY.visibility">visible</option>
        <option name="charting.axisTitleY2.visibility">visible</option>
        <option name="charting.axisX.scale">linear</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.axisY2.enabled">0</option>
        <option name="charting.axisY2.scale">inherit</option>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.bubbleMaximumSize">50</option>
        <option name="charting.chart.bubbleMinimumSize">10</option>
        <option name="charting.chart.bubbleSizeBy">area</option>
        <option name="charting.chart.nullValueMode">gaps</option>
        <option name="charting.chart.showDataLabels">none</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.chart.stackMode">default</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.drilldown">all</option>
        <option name="charting.layout.splitSeries">0</option>
        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
</form>`,
    comments: `Tested with FPI. Does not use datamodels`
  },
  {
    dashboardName: `Timechart of Port Activity Over Time`,
    domain: `DOMAIN`,
    dashboardXML: `|tstats summariesonly=t count from  datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip!=10.* All_Traffic.dest_ip!=192.168.0.0/16  All_Traffic.dest_ip!=172.16.0.0/12 All_Traffic.dest_ip!=10.0.0.0/8 All_Traffic.dest_ip!=255.255.255.255 All_Traffic.dest_ip!=4.2.2.1 All_Traffic.dest_ip!=4.2.2.2 All_Traffic.dest_ip!=4.2.2.3 All_Traffic.dest_ip!=4.2.2.4 All_Traffic.dest_ip!=4.2.2.5 All_Traffic.dest_ip!=4.2.2.6  All_Traffic.dest_ip!=8.8.8.8 All_Traffic.dest_ip!=8.8.4.4 All_Traffic.dest_ip!=239.255.255.250 All_Traffic.action!="blocked" by sourcetype,All_Traffic.src_ip,All_Traffic.dest_ip,All_Traffic.action,All_Traffic.dest_port
|\`drop_dm_object_name("All_Traffic")\`
|iplocation dest_ip
|where NOT Country="United States"
|geostats count by Country globallimit=0`,
    comments: `Network Data Model`
  },
  {
    dashboardName: `Outbound Foreign Network Traffic`,
    domain: `DOMAIN`,
    dashboardXML: `|tstats summariesonly=t allow_old_summaries=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_ip!=0.0.0.0 All_Traffic.dest_ip!=255.255.255.255 (All_Traffic.src_ip="10.*" OR All_Traffic.src_ip="192.168*" OR All_Traffic.src_ip="172.*") (NOT All_Traffic.dest_port=443) (NOT All_Traffic.dest_port=80) (NOT All_Traffic.dest_port=53) (NOT All_Traffic.dest_port=123) All_Traffic.direction=outbound by _time,All_Traffic.src_ip,All_Traffic.dest_ip,All_Traffic.dest_port,All_Traffic.direction,All_Traffic.action,sourcetype span=1hr
|\`drop_dm_object_name("All_Traffic")\`
| where NOT cidrmatch("172.16.0.0/12",dest_ip) | where NOT cidrmatch("10.0.0.0/8",dest_ip) | where NOT cidrmatch("192.168.0.0/16",dest_ip) | sort dest_port`,
    comments:`Network Data Model`
  },
  {
    dashboardName:`All Outbound Network Request Traffic`,
    domain: `DOMAIN`,
    dashboardXML:`|tstats summariesonly=t allow_old_summaries=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_ip!=0.0.0.0 All_Traffic.dest_ip!=255.255.255.255 (All_Traffic.src_ip="10.*" OR All_Traffic.src_ip="192.168*" OR All_Traffic.src_ip="172.*") (NOT All_Traffic.dest_port=443) (NOT All_Traffic.dest_port=80) (NOT All_Traffic.dest_port=53) (NOT All_Traffic.dest_port=123) All_Traffic.direction=outbound by _time,All_Traffic.src_ip,All_Traffic.dest_ip,All_Traffic.dest_port,All_Traffic.direction,All_Traffic.action,sourcetype span=1hr
|\`drop_dm_object_name("All_Traffic")\`
| where NOT cidrmatch("172.16.0.0/12",dest_ip) | where NOT cidrmatch("10.0.0.0/8",dest_ip) | where NOT cidrmatch("192.168.0.0/16",dest_ip) | sort dest_port`,
    comments:`Network Data Model`
  },
  {
    dashboardName:`Top 20 IDS Threat Traffic Generated from External IP's`,
    domain: `DOMAIN`,
    dashboardXML:`|tstats summariesonly=t allow_old_summaries=true count from datamodel=Intrusion_Detection.IDS_Attacks where (IDS_Attacks.src!=8.8.8.8 IDS_Attacks.src!=8.8.4.4)  by _time, IDS_Attacks.signature, IDS_Attacks.src, IDS_Attacks.dest, sourcetype span=24hr |\`drop_dm_object_name("IDS_Attacks")\`
| where NOT cidrmatch("172.16.0.0/12",src) | where NOT cidrmatch("10.0.0.0/8",src) | where NOT cidrmatch("192.168.0.0/16",src)  | iplocation src | top src, Country limit=20`,
    comments:`IDS Data Model`
  },
  {
    dashboardName:`Top 20 IDS Threat Traffic Generated from Internal IP's`,
    domain: `DOMAIN`,
    dashboardXML:`|tstats summariesonly=t allow_old_summaries=true count from datamodel=Intrusion_Detection.IDS_Attacks where sourcetype="pan:threat" (IDS_Attacks.src="10.*" OR IDS_Attacks.src="192.168*" OR IDS_Attacks.src="172.16*") by _time, IDS_Attacks.signature, IDS_Attacks.src, IDS_Attacks.dest, sourcetype span=24hr | top IDS_Attacks.dest limit=20`,
    comments:`IDS Data Model`
  },
];

let dropAndSeedDashboards = function dropAndSeedDashboards() {
  return new Promise( (resolve, reject) => {
    db.Dashboard.remove({})
      .then( () => {
        function asyncCreateDoc(doc) {
          return new Promise(resolveAsync => {
            db.Dashboard.create(doc)
              .then(createdDoc => {
                resolveAsync();
              });
          });
        }
        let createInteractions = dashboardsList.map(asyncCreateDoc);
        let createResults = Promise.all(createInteractions);
        createResults.then( () => {
          resolve();
        }).catch(err => {
          console.log('WAS NOT ABLE TO CREATE ALL DASHBOARDS', err);
          reject();
        });
      }).catch(err => {
        console.log('WAS NOT ABLE TO CREATE ALL DASHBOARDS', err);
        reject();
      });
    });
  };

// let dropAndSeedUseCases = function() {
//   return new Promise( (resolve, reject) => {
//     db.UseCase.remove({})
//       .then( () => {
//         function asyncCreateDoc(doc) {
//           return new Promise(resolveAsync => {
//             db.UseCase.create(doc)
//               .then(createdDoc => {
//                 // console.log('CREATED DOCUMENT: ' + createdDoc);
//                 resolveAsync();
//               });
//           });
//         }
//         let createInteractions = useCaseList.map(asyncCreateDoc);
//         let createResults = Promise.all(createInteractions);
//         createResults.then( () => {
//           // console.log('DONE WITH CREATING USECASES');
//           resolve();
//         }).catch(err => {
//           console.log('WAS NOT ABLE TO CREATE ALL USECASES', err);
//           reject();
//         });
//       }).catch(err => {
//         console.log('WAS NOT ABLE TO REMOVE ALL USECASES: ', err);
//         reject();
//       });
//     });
// };

// SEED

dropAndSeedLogSrcs()
  .then( () => {
    console.log('LOG SOURCES SEEDED!');
    dropAndSeedUseCases().then( () => {
      console.log('USECASES SEEDED!');
      dropAndSeedDashboards().then( () => {
        console.log('DATABASE SEEDED!');
        process.exit();
      });
    });
  });
