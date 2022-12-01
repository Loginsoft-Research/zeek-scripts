@load base/frameworks/notice
@load base/protocols/http

module cve_2022_22549;

export{
	redef enum Notice::Type +={
		cve_2022_22549_exploit,
	};

}


event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
	if(c$http?$method)
	{
		local method1=match_pattern(c$http$uri,/catalog-portal\/ui\/oauth\/verify\?error=&deviceUdid=/);
		if(method1$matched)
		{	NOTICE([$note=cve_2022_22549_exploit,
			$conn=c,
			$msg="Possible to (cve-2022-22549) exploit",
			$sub = "Server Side Template Injection"
		]);
			
		}
		else
		{
			local method2=match_pattern(c$http$uri,/freemarker\.template\.utility\.Execute/);
			if(method2$matched)
			{
				NOTICE([$note=cve_2022_22549_exploit,
				$conn=c,
				$msg="Possible to (cve-2022-22549) exploit",
				$sub="Server Side Template Injection"
				]);
			}
		}
	}

}