var q;
function g(){
	q = g.caller;
	return 7;
}


var a = [1, 2, 3];
a.length = 4;
Object.defineProperty(Array.prototype, "3", {get : g});
[4, 5, 6].concat(a);
q(0x77777777, 0x77777777, 0);
