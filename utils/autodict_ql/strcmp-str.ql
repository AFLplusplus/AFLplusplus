import cpp 

/// function : strcmp

from FunctionCall fucall, Expr size
where
    fucall.getTarget().hasName("strcmp")
select fucall.getArgument(_).getValueText()