#!/usr/bin/php5
<?php
require_once("functions.php");

$longopts = array("url:","mode:","help");
$options = getopt(NULL,$longopts);

if(empty($options))
{
	die("Read help menu for more informations : $argv[0] --help\n");
}

switch ($options) 
{
	case (isset($options['url']) AND isset($options['mode']) AND isValidMode($options["mode"]) == 1):
		$url = $options['url'];
		include("error_based.php");
	break;
	case (isset($options["help"])):
		include("help.php");
	break;
	default:
		die("Read help menu for more informations : $argv[0] --help\n");
	break;
}
?>
													
