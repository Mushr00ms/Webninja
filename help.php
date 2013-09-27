<?php
		echo"
WebNinja[v3.0] - Developer : Crown ~ automatic SQL injection tool

Usage : $argv[0] [options]

Options:

  --help         Show the help menu then stop the script
  --url          Specify the url of the target
  --mode         Specify which modes you want to use : error_based

Example : 

  $argv[0] --url=\"http://site.com/index.php?id=6\" --mode=error_based

";
?>