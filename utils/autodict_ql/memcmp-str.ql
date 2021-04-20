import cpp 

/// function :  memcmp trace

from FunctionCall fucall, Expr size
where
    fucall.getTarget().hasName("memcmp")
select fucall.getArgument(_).getValueText()	