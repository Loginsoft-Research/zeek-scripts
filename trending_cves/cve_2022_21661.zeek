@load base/protocols/http
@load base/frameworks/notice

module Wordpress;

export{
	redef enum Notice::Type +={
		cve_2022_21661,

	};
	const conn_duration_time = 800 msecs &redef;	
}

function con_limit(c:connection){
    if ( c$duration > conn_duration_time )
    {
		NOTICE([$note=cve_2022_21661,
		$conn=c,
		$msg="Possible CVE-2022_21661 exploit",
		$sub="Bruteforce for login credentials"
		]);
	}
}
event http_entity_data (c: connection, is_orig: bool, length: count, data: string)

{
	local user_info = match_pattern(c$http$uri,/\/wp-admin\/admin-ajax\.php\?action=ecsload/);
	if(user_info$matched)
	{
		con_limit(c);
	}	
	local data_match:string="query";
	if(data_match in data) 
	{
		local terms_match=match_pattern(data,/terms.*or.if.*select/);
		if(terms_match$matched)
		{
			NOTICE([$note=cve_2022_21661,
			$conn=c,
			$msg="Possible CVE-2022_21661 exploit in Wordpress",
			$sub=""
			]);
		}
		
	}

}