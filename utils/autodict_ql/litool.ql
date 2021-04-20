import cpp

class HexOrOctLiteral extends Literal{
    HexOrOctLiteral(){
      (this instanceof HexLiteral) or (this instanceof OctalLiteral)
    }
}

from HexOrOctLiteral lit
select lit.getValueText()
