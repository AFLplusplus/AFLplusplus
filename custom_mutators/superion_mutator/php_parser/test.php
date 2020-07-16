<?php
$a=5;
$b=3;
function t1()
{  
    global $a,$b;
    echo $a-$b;
}
t1();

echo PHP_EOL;

function t2()
{
    echo $GLOBALS['a']-$GLOBALS['b'];
}
t2();
?>
