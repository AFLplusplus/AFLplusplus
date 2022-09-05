#!/bin/bash

test -z "$1" -o -z "$2" -o "$1" = "-h" -o "$1" = "-hh" -o "$1" = "--help" -o '!' -d "$1" && {
  echo "Syntax: [-n]  $0 out-directory file.csv [\"tools/target --opt @@\"]"
  echo Option -n will suppress the CSV header.
  echo If the target execution command is supplied then also edge coverage is gathered.
  exit 1
}

function getval() {
  VAL=""
  if [ "$file" != "${file/$1/}" ]; then
    TMP="${file/*$1:/}"
    VAL="${TMP/,*/}"
  fi
}

SKIP=
if [ "$1" = "-n" ]; then
  SKIP=1
  shift
fi

test -n "$4" && { echo "Error: too many commandline options. Target command and options including @@ have to be passed within \"\"!"; exit 1; }

test -d "$1"/queue && OUT="$1/queue" || OUT="$1"

OK=`ls $OUT/id:000000,time:0,orig:* 2> /dev/null`
if [ -n "$OK" ]; then
  LISTCMD="ls $OUT/id:"*
else
  LISTCMD="ls -tr $OUT/"
fi

ID=;SRC=;TIME=;OP=;POS=;REP=;EDGES=;EDGES_TOTAL=;
DIR="$OUT/../stats"
rm -rf "$DIR"
> "$2" || exit 1
mkdir "$DIR" || exit 1
> "$DIR/../edges.txt" || exit 1

{

  if [ -z "$SKIP" ]; then
    echo "time;\"filename\";id;src;new_cov;edges;total_edges;\"op\";pos;rep;unique_edges"
  fi

  $LISTCMD | grep -v ,sync: | sed 's/.*id:/id:/g' | while read file; do

    if [ -n "$3" ]; then

      TMP=${3/@@/$OUT/$file}
      
      if [ "$TMP" = "$3" ]; then
    
        cat "$OUT/$file" | afl-showmap -o "$DIR/$file" -q -- $3 >/dev/null 2>&1
        
      else
      
        afl-showmap -o "$DIR/$file" -q -- $TMP >/dev/null 2>&1
      
      fi
    
      { cat "$DIR/$file" | sed 's/:.*//' ; cat "$DIR/../edges.txt" ; } | sort -nu > $DIR/../edges.txt.tmp
      mv $DIR/../edges.txt.tmp $DIR/../edges.txt
      EDGES=$(cat "$DIR/$file" | wc -l)
      EDGES_TOTAL=$(cat "$DIR/../edges.txt" | wc -l)

    fi

    getval id; ID="$VAL"
    getval src; SRC="$VAL"
    getval time; TIME="$VAL"
    getval op; OP="$VAL"
    getval pos; POS="$VAL"
    getval rep; REP="$VAL"
    if [ "$file" != "${file/+cov/}" ]; then
      COV=1
    else
      COV=""
    fi

    if [ -n "$3" -a -s "$DIR/../edges.txt" ]; then
      echo "$TIME;\"$file\";$ID;$SRC;$COV;$EDGES;$EDGES_TOTAL;\"$OP\";$POS;$REP;UNIQUE$file"
    else
      echo "$TIME;\"$file\";$ID;$SRC;$COV;;;\"$OP\";$POS;$REP;"
    fi

  done

} | tee "$DIR/../queue.csv" > "$2" || exit 1

if [ -n "$3" -a -s "$DIR/../edges.txt" ]; then

  cat "$DIR/"* | sed 's/:.*//' | sort -n | uniq -c | grep -E '^[ \t]*1 ' | awk '{print$2}' > $DIR/../unique.txt

  if [ -s "$DIR/../unique.txt" ]; then

    ls "$DIR/id:"* | grep -v ",sync:" |sed 's/.*\/id:/id:/g' | while read file; do

      CNT=$(sed 's/:.*//' "$DIR/$file" | tee "$DIR/../tmp.txt" | wc -l)
      DIFF=$(diff -u "$DIR/../tmp.txt" "$DIR/../unique.txt" | grep -E '^-[0-9]' | wc -l)
      UNIQUE=$(($CNT - $DIFF))
      sed -i "s/;UNIQUE$file/;$UNIQUE/" "$DIR/../queue.csv" "$2"

    done
    
    rm -f "$DIR/../tmp.txt"

  else
    
    sed -i 's/;UNIQUE.*/;/' "$DIR/../queue.csv" "$2"
  
  fi  

fi

mv "$DIR/../queue.csv" "$DIR/queue.csv"
if [ -e "$DIR/../edges.txt" ]; then mv "$DIR/../edges.txt" "$DIR/edges.txt"; fi
if [ -e "$DIR/../unique.txt" ]; then mv "$DIR/../unique.txt" "$DIR/unique.txt"; fi

echo "Created $2"
