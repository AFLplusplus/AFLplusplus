function foo()
{
    var o = Error();
    for(let i in o)
    {
        o[i];
    }
}

var bb = foo();
