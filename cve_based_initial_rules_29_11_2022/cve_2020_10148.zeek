@load base/protocols/http
@load base/frameworks/notice


module Suricatta_rule;


export{
	redef enum Notice::Type += {
		CVE_2020_10148,
	};
}

event http_entity_data(c:connection,is_orig:bool,length:count,data:string)
{	

	if (c$http?$method)
		# print (c$http$uri);
		{	
			local uri_match = match_pattern(c$http$uri, /(Script|Web)Resource\.axd|i18n\.ashx|Skipi18n/);
			if (uri_match$matched) 
			 	{
				NOTICE ([$note=CVE_2020_10148,
					$conn=c,
					$msg=fmt("Exploit CVE-2020-10148 on SolarWinds Orion API."),
					$sub=fmt("web-application-attack")
					# $identifier =(c$id)
					]);
			}

			local uri_match1 = match_pattern(c$http$uri,/SWNetPerfMon.dbv=|web.config(v=[0-9]|[0-9])|Orion|invalid.aspx.js/);
			if(uri_match1$matched)
				# print(c$http$uri);	  
				{
				NOTICE ([$note=CVE_2020_10148,
					$conn=c,
					$msg=fmt("Exploit CVE-2020-10148 on SolarWinds Orion API."),
					$sub=fmt("web-application-attack")
					# $identifier =(c$id)
					]);
			}
		}
}


