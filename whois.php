<?php
function get_whois_data($send, $server) {
	$r = '';
	$fp = @fsockopen($server, 43, $errno, $errstr, 10);
	if (!$fp) throw new Exception('connecting to '.$server.' failed');
	fwrite($fp, $send."\r\n");
	while(!feof($fp)) $r .= fread($fp, 1024);
	fclose($fp);
	return $r;
}

function get_tld_server($tld) {
	if (file_exists("tlds/$tld.json")) {
		$r = json_decode(file_get_contents("tlds/$tld.json"), true);
		if ($r['server'] === null && time() - $r['time'] < 1296000) return null;
		if ($r['server'] !== null && time() - $r['time'] < 51840000) return $r['server'];
	}
	$wd = get_whois_data($tld, 'whois.iana.org');
	if (preg_match('/\s*whois:[ \t]*([0-9a-z_\-\.]+\.(?:xn--)?[0-9a-z]+)\s/i', $wd, $matches)) {
		file_put_contents("tlds/$tld.json", json_encode(array('server' => $matches[1], 'time' => time())));
		return $matches[1];
	}
	file_put_contents("tlds/$tld.json", json_encode(array('server' => null, 'time' => time())));
	return null;
}

function lookup_domain($domain, $require_refresh = false) {
	$domain = strtolower($domain);
	$dotCount = substr_count($domain, '.');
	if ($dotCount > 2 or $dotCount < 1) {
		throw new Exception('tld of domain '.$domain.' is not supported');
	}
	if (!preg_match('/^[0-9a-z\-\.]+$/', $domain)) {
		throw new Exception('domain syntax error');
	}
	if (file_exists("domains/$domain.json")) {
		$j = json_decode(file_get_contents("domains/$domain.json"), true);
		$time_offset = time() - $j['time'];
		if ($time_offset < 3600) return $j;
		if (!$require_refresh and $time_offset < 1296000) return $j;
	}
	$tld_server = get_tld_server(substr($domain, strrpos($domain, '.') + 1));
	if ($tld_server === null) throw new Exception("no whois server avaliable for $domain");
	$queried_whois_server = array();
	$whois_data = array();
	for ($i = 0; $i < 5; $i++) {
		if (in_array($tld_server, $queried_whois_server)) break;
		$queried_whois_server[] = $tld_server;
		try {
			$whois_data[$i] = array('server' => $tld_server, 'data' => get_whois_data($domain, $tld_server));
			if (preg_match('/\n\s*(?:registrar )?whois(?: server)?:[ \t]*([0-9a-z_\-\.]+\.(?:xn--)?[0-9a-z]+)\s/i', $whois_data[$i]['data'], $wm)) {
				$tld_server = strtolower($wm[1]);
				continue;
			}
		} catch (Exception $e) {
			$whois_data[$i] = array('server' => $tld_server, 'data' => null);
		}
		break;
	}
	$j = array('data' => $whois_data, 'time' => time());
	file_put_contents("domains/$domain.json", json_encode($j));
	return $j;
}

header('Content-Type: application/json');
$refresh = (isset($_GET['nocache']) and $_GET['nocache'] === '1')? true: false;
$ed = array('error' => null, 'result' => null);
try {
	$ed['result'] = lookup_domain($_GET['domain'], $refresh);
} catch (Exception $e) {
	$ed['error'] = $e->getMessage();
}
echo json_encode($ed);
