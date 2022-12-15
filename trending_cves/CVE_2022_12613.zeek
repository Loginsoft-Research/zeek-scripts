@load base/protocols/http
@load base/frameworks/notice

# need to validate 

module cve_2022_12613;

export{
	redef enum Notice::Type +={
		cve_2022_12613_exploit,
	};
	
}
event http_entity_data (c: connection, is_orig: bool, length: count, data: string)

{
	local login_match=match_pattern(c$http$uri,/index.php/);
	if(login_match$matched)
	{			
		local target_match:pattern=/target\=index.php/;
		local server_match:pattern=/server\=[1]/;
		if(target_match in data && server_match in data)
		{
			NOTICE([$note=cve_2022_12613_exploit,
			$conn=c,
			$msg="Possible cve_2022_12613_exploit"
			]);

		}			
		
	}			
	
# # checking that there is a Sql_server connection or not

	local pay_load_match=match_pattern(c$http$uri, /\/import.php/);
	if(pay_load_match$matched)
	{
		local query_match:pattern=/sql_query\=select+/;
		local sql_server_match:pattern=/goto\=server_sql\.php/;
		local processing_match:pattern=/SQL\=Go/;

		if(query_match in data && sql_server_match in data && processing_match in data)
		{
			NOTICE([$note=cve_2022_12613_exploit,
			$conn=c,
			$msg="Possible cve_2022_12613_exploit in phpMyAdmin ",
			$sub="Improper Authentication"
			]);
		}
	}
	
}
